use super::WindowsHostError;
use crate::office_private_desktop::{office_export_output_path, OfficePrivateDesktop};
use std::ffi::c_void;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

const S_OK: i32 = 0;
const COINIT_APARTMENTTHREADED: u32 = 0x2;
const CLSCTX_LOCAL_SERVER: u32 = 0x4;
const DISPATCH_METHOD: u16 = 0x1;
const DISPATCH_PROPERTYGET: u16 = 0x2;
const DISPATCH_PROPERTYPUT: u16 = 0x4;
const DISPID_PROPERTYPUT: i32 = -3;
const VT_EMPTY: u16 = 0;
const VT_I4: u16 = 3;
const VT_BSTR: u16 = 8;
const VT_DISPATCH: u16 = 9;
const VT_BOOL: u16 = 11;
const VARIANT_TRUE: i16 = -1;

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const IID_NULL: Guid = Guid {
    data1: 0,
    data2: 0,
    data3: 0,
    data4: [0; 8],
};
const IID_IDISPATCH: Guid = Guid {
    data1: 0x0002_0400,
    data2: 0,
    data3: 0,
    data4: [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
};
const CLSID_WORD_APPLICATION: Guid = Guid {
    data1: 0x0002_09ff,
    data2: 0,
    data3: 0,
    data4: [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
};

#[repr(C)]
union VariantData {
    int_value: i32,
    bool_value: i16,
    bstr_value: *mut u16,
    dispatch_value: *mut RawDispatch,
    padding: [u64; 2],
}

#[repr(C)]
struct Variant {
    variant_type: u16,
    reserved1: u16,
    reserved2: u16,
    reserved3: u16,
    data: VariantData,
}

impl Variant {
    fn empty() -> Self {
        Self {
            variant_type: VT_EMPTY,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            data: VariantData { padding: [0; 2] },
        }
    }
}

impl Drop for Variant {
    fn drop(&mut self) {
        // SAFETY: this value is initialized as a valid VARIANT and is cleared once.
        unsafe {
            let _ = VariantClear((self as *mut Variant).cast());
        }
    }
}

#[repr(C)]
struct DispatchParameters {
    arguments: *mut Variant,
    named_argument_ids: *mut i32,
    argument_count: u32,
    named_argument_count: u32,
}

#[repr(C)]
struct ExceptionInfo {
    code: u16,
    reserved: u16,
    source: *mut u16,
    description: *mut u16,
    help_file: *mut u16,
    help_context: u32,
    reserved_pointer: *mut c_void,
    deferred_fill: *mut c_void,
    status_code: i32,
}

impl ExceptionInfo {
    fn empty() -> Self {
        Self {
            code: 0,
            reserved: 0,
            source: null_mut(),
            description: null_mut(),
            help_file: null_mut(),
            help_context: 0,
            reserved_pointer: null_mut(),
            deferred_fill: null_mut(),
            status_code: 0,
        }
    }

    fn clear(&mut self) {
        // SAFETY: these fields are either null or BSTRs allocated by COM for this call.
        unsafe {
            if !self.source.is_null() {
                SysFreeString(self.source);
            }
            if !self.description.is_null() {
                SysFreeString(self.description);
            }
            if !self.help_file.is_null() {
                SysFreeString(self.help_file);
            }
        }
        self.source = null_mut();
        self.description = null_mut();
        self.help_file = null_mut();
    }
}

#[repr(C)]
struct RawDispatch {
    vtable: *const RawDispatchVtable,
}

#[repr(C)]
struct RawDispatchVtable {
    query_interface:
        unsafe extern "system" fn(*mut RawDispatch, *const Guid, *mut *mut c_void) -> i32,
    add_ref: unsafe extern "system" fn(*mut RawDispatch) -> u32,
    release: unsafe extern "system" fn(*mut RawDispatch) -> u32,
    get_type_info_count: unsafe extern "system" fn(*mut RawDispatch, *mut u32) -> i32,
    get_type_info: unsafe extern "system" fn(*mut RawDispatch, u32, u32, *mut *mut c_void) -> i32,
    get_ids_of_names: unsafe extern "system" fn(
        *mut RawDispatch,
        *const Guid,
        *mut *mut u16,
        u32,
        u32,
        *mut i32,
    ) -> i32,
    invoke: unsafe extern "system" fn(
        *mut RawDispatch,
        i32,
        *const Guid,
        u32,
        u16,
        *mut DispatchParameters,
        *mut Variant,
        *mut ExceptionInfo,
        *mut u32,
    ) -> i32,
}

struct Dispatch(*mut RawDispatch);

impl Drop for Dispatch {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Dispatch owns one COM reference obtained from COM or a VARIANT.
            unsafe {
                ((*(*self.0).vtable).release)(self.0);
            }
        }
    }
}

impl Dispatch {
    fn member_id(&self, name: &'static str) -> Result<i32, WindowsHostError> {
        let mut wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut name_pointer = wide.as_mut_ptr();
        let mut member_id = 0_i32;
        // SAFETY: the dispatch pointer and null-terminated name remain valid for the call.
        let status = unsafe {
            ((*(*self.0).vtable).get_ids_of_names)(
                self.0,
                &IID_NULL,
                &raw mut name_pointer,
                1,
                0x0400,
                &raw mut member_id,
            )
        };
        check_status(status, &format!("IDispatch::GetIDsOfNames({name})"))?;
        Ok(member_id)
    }

    fn invoke(
        &self,
        name: &'static str,
        flags: u16,
        arguments: Vec<ComArgument<'_>>,
    ) -> Result<Variant, WindowsHostError> {
        let member_id = self.member_id(name)?;
        let mut values = arguments
            .into_iter()
            .rev()
            .map(ComArgument::into_variant)
            .collect::<Result<Vec<_>, _>>()?;
        let mut property_put_id = DISPID_PROPERTYPUT;
        let property_put = flags == DISPATCH_PROPERTYPUT;
        let mut parameters = DispatchParameters {
            arguments: if values.is_empty() {
                null_mut()
            } else {
                values.as_mut_ptr()
            },
            named_argument_ids: if property_put {
                &raw mut property_put_id
            } else {
                null_mut()
            },
            argument_count: u32::try_from(values.len())
                .map_err(|_| WindowsHostError::new("COM argument count overflow"))?,
            named_argument_count: u32::from(property_put),
        };
        let mut result = Variant::empty();
        let mut exception = ExceptionInfo::empty();
        let mut argument_error = 0_u32;
        // SAFETY: all COM pointers and DISPPARAMS storage remain valid during Invoke.
        let status = unsafe {
            ((*(*self.0).vtable).invoke)(
                self.0,
                member_id,
                &IID_NULL,
                0x0400,
                flags,
                &raw mut parameters,
                &raw mut result,
                &raw mut exception,
                &raw mut argument_error,
            )
        };
        exception.clear();
        check_status(status, name)?;
        Ok(result)
    }

    fn property_dispatch(&self, name: &'static str) -> Result<Dispatch, WindowsHostError> {
        take_dispatch(self.invoke(name, DISPATCH_PROPERTYGET, Vec::new())?, name)
    }

    fn property_i32(&self, name: &'static str) -> Result<i32, WindowsHostError> {
        let result = self.invoke(name, DISPATCH_PROPERTYGET, Vec::new())?;
        if result.variant_type == VT_I4 {
            // SAFETY: the active VARIANT arm is selected by VT_I4.
            return Ok(unsafe { result.data.int_value });
        }
        if result.variant_type == VT_BOOL {
            // SAFETY: the active VARIANT arm is selected by VT_BOOL.
            return Ok(i32::from(unsafe { result.data.bool_value }));
        }
        Err(WindowsHostError::new(format!(
            "Word property {name} returned an unexpected type"
        )))
    }

    fn put_i32(&self, name: &'static str, value: i32) -> Result<(), WindowsHostError> {
        self.invoke(
            name,
            DISPATCH_PROPERTYPUT,
            vec![ComArgument::Integer(value)],
        )?;
        Ok(())
    }

    fn put_bool(&self, name: &'static str, value: bool) -> Result<(), WindowsHostError> {
        self.invoke(
            name,
            DISPATCH_PROPERTYPUT,
            vec![ComArgument::Boolean(value)],
        )?;
        Ok(())
    }

    fn put_text(&self, name: &'static str, value: &str) -> Result<(), WindowsHostError> {
        self.invoke(name, DISPATCH_PROPERTYPUT, vec![ComArgument::Text(value)])?;
        Ok(())
    }

    fn method(
        &self,
        name: &'static str,
        arguments: Vec<ComArgument<'_>>,
    ) -> Result<(), WindowsHostError> {
        self.invoke(name, DISPATCH_METHOD, arguments)?;
        Ok(())
    }

    fn method_i32(
        &self,
        name: &'static str,
        arguments: Vec<ComArgument<'_>>,
    ) -> Result<i32, WindowsHostError> {
        let result = self.invoke(name, DISPATCH_METHOD, arguments)?;
        if result.variant_type != VT_I4 {
            return Err(WindowsHostError::new(format!(
                "Word method {name} returned an unexpected type"
            )));
        }
        // SAFETY: the active VARIANT arm is selected by VT_I4.
        Ok(unsafe { result.data.int_value })
    }

    fn method_dispatch(
        &self,
        name: &'static str,
        arguments: Vec<ComArgument<'_>>,
    ) -> Result<Dispatch, WindowsHostError> {
        take_dispatch(self.invoke(name, DISPATCH_METHOD, arguments)?, name)
    }
}

enum ComArgument<'a> {
    Integer(i32),
    Boolean(bool),
    Text(&'a str),
    Dispatch(&'a Dispatch),
}

impl ComArgument<'_> {
    fn into_variant(self) -> Result<Variant, WindowsHostError> {
        let mut value = Variant::empty();
        match self {
            Self::Integer(integer) => {
                value.variant_type = VT_I4;
                value.data.int_value = integer;
            }
            Self::Boolean(boolean) => {
                value.variant_type = VT_BOOL;
                value.data.bool_value = if boolean { VARIANT_TRUE } else { 0 };
            }
            Self::Text(text) => {
                let wide = text.encode_utf16().collect::<Vec<_>>();
                let length = u32::try_from(wide.len())
                    .map_err(|_| WindowsHostError::new("COM text length overflow"))?;
                // SAFETY: SysAllocStringLen copies the supplied UTF-16 buffer.
                let bstr = unsafe { SysAllocStringLen(wide.as_ptr(), length) };
                if bstr.is_null() && !wide.is_empty() {
                    return Err(WindowsHostError::new("BSTR allocation failed"));
                }
                value.variant_type = VT_BSTR;
                value.data.bstr_value = bstr;
            }
            Self::Dispatch(dispatch) => {
                // SAFETY: AddRef creates the reference owned by the argument VARIANT.
                unsafe {
                    ((*(*dispatch.0).vtable).add_ref)(dispatch.0);
                }
                value.variant_type = VT_DISPATCH;
                value.data.dispatch_value = dispatch.0;
            }
        }
        Ok(value)
    }
}

fn take_dispatch(mut value: Variant, label: &str) -> Result<Dispatch, WindowsHostError> {
    if value.variant_type != VT_DISPATCH {
        return Err(WindowsHostError::new(format!(
            "Word {label} returned VARIANT type {} instead of an automation object",
            value.variant_type
        )));
    }
    // SAFETY: the active VARIANT arm is selected by VT_DISPATCH.
    let pointer = unsafe { value.data.dispatch_value };
    if pointer.is_null() {
        return Err(WindowsHostError::new(format!(
            "Word {label} returned a null automation object"
        )));
    }
    value.variant_type = VT_EMPTY;
    value.data.padding = [0; 2];
    Ok(Dispatch(pointer))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordAutomationOperationV1 {
    AppendParagraph { text: String },
    InsertTable { cells: Vec<Vec<String>> },
    InsertImage { image_path: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordAutomationReceiptV1 {
    pub word_process_id: u32,
    pub visible: bool,
    pub display_alerts: i32,
    pub automation_security: i32,
    pub operation_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordPdfExportReceiptV1 {
    pub word_process_id: u32,
    pub page_count: u32,
    pub private_desktop: bool,
    pub visible: bool,
    pub display_alerts: i32,
    pub automation_security: i32,
    pub pdfa_requested: bool,
    pub output_fresh_and_stable: bool,
}

pub fn export_word_document_pdf(
    source_path: &Path,
    destination_path: &Path,
    pdfa_requested: bool,
) -> Result<WordPdfExportReceiptV1, WindowsHostError> {
    validate_pdf_paths(source_path, destination_path, "docx")?;
    let source_path = office_compatible_path(&source_path.canonicalize().map_err(|error| {
        WindowsHostError::new(format!("Word source canonicalization failed: {error}"))
    })?);
    let destination_path = office_export_output_path(destination_path)?;
    let before_word_pids = installed_word_process_ids()?;
    let private_desktop = OfficePrivateDesktop::enter("word")?;
    let apartment = ComApartment::initialize()?;
    let application = create_word_application()?;
    let process_id = resolve_new_word_process_id(&before_word_pids)?;
    let original_security = application.property_i32("AutomationSecurity")?;
    let original_alerts = application.property_i32("DisplayAlerts")?;
    application.put_bool("Visible", false)?;
    application.put_i32("DisplayAlerts", 0)?;
    application.put_i32("AutomationSecurity", 3)?;
    let result = (|| {
        let documents = application.property_dispatch("Documents")?;
        let source = source_path.to_string_lossy();
        documents.method("Open", vec![ComArgument::Text(&source)])?;
        let document = application.property_dispatch("ActiveDocument")?;
        let page_count = document.method_i32(
            "ComputeStatistics",
            vec![ComArgument::Integer(2), ComArgument::Boolean(true)],
        )?;
        if page_count <= 0 || page_count > 500 {
            return Err(WindowsHostError::new("Word page count exceeds bounds"));
        }
        let destination = destination_path.to_string_lossy();
        let export = document.method(
            "ExportAsFixedFormat",
            vec![
                ComArgument::Text(&destination),
                ComArgument::Integer(17),
                ComArgument::Boolean(false),
                ComArgument::Integer(0),
                ComArgument::Integer(0),
                ComArgument::Integer(1),
                ComArgument::Integer(1),
                ComArgument::Integer(0),
                ComArgument::Boolean(false),
                ComArgument::Boolean(true),
                ComArgument::Integer(0),
                ComArgument::Boolean(true),
                ComArgument::Boolean(false),
                ComArgument::Boolean(pdfa_requested),
            ],
        );
        let close = document.method("Close", vec![ComArgument::Boolean(false)]);
        export?;
        close?;
        u32::try_from(page_count)
            .map_err(|_| WindowsHostError::new("Word page count conversion failed"))
    })();
    let _ = application.put_i32("AutomationSecurity", original_security);
    let _ = application.put_i32("DisplayAlerts", original_alerts);
    let _ = application.method("Quit", vec![ComArgument::Boolean(false)]);
    drop(application);
    drop(apartment);
    wait_for_owned_word_exit(process_id)?;
    private_desktop.leave()?;
    let page_count = result?;
    wait_for_stable_pdf(&destination_path)?;
    Ok(WordPdfExportReceiptV1 {
        word_process_id: process_id,
        page_count,
        private_desktop: true,
        visible: false,
        display_alerts: 0,
        automation_security: 3,
        pdfa_requested,
        output_fresh_and_stable: true,
    })
}

fn validate_pdf_paths(
    source_path: &Path,
    destination_path: &Path,
    source_extension: &str,
) -> Result<(), WindowsHostError> {
    if !source_path.is_file()
        || destination_path.exists()
        || source_path == destination_path
        || !source_path
            .extension()
            .is_some_and(|value| value.eq_ignore_ascii_case(source_extension))
        || !destination_path
            .extension()
            .is_some_and(|value| value.eq_ignore_ascii_case("pdf"))
        || !destination_path.parent().is_some_and(Path::is_dir)
    {
        return Err(WindowsHostError::new("Word PDF export paths are invalid"));
    }
    Ok(())
}

fn wait_for_stable_pdf(path: &Path) -> Result<(), WindowsHostError> {
    let mut previous = 0_u64;
    let mut stable = 0_u32;
    for _ in 0..100 {
        let size = std::fs::metadata(path)
            .map(|value| value.len())
            .unwrap_or_default();
        if size > 8 && size == previous {
            stable = stable.saturating_add(1);
            if stable >= 3 {
                let header = std::fs::read(path).map_err(|error| {
                    WindowsHostError::new(format!("Word PDF read failed: {error}"))
                })?;
                if header.starts_with(b"%PDF-") {
                    return Ok(());
                }
                return Err(WindowsHostError::new("Word output is not a PDF"));
            }
        } else {
            stable = 0;
        }
        previous = size;
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(WindowsHostError::new(
        "Word PDF output did not become stable",
    ))
}

pub fn execute_word_document_operation(
    document_path: &Path,
    operation: &WordAutomationOperationV1,
) -> Result<WordAutomationReceiptV1, WindowsHostError> {
    if !document_path.is_file() {
        return Err(WindowsHostError::new("Word document path is not a file"));
    }
    validate_operation(operation)?;
    let document_path = document_path.canonicalize().map_err(|error| {
        WindowsHostError::new(format!("Word document canonicalization failed: {error}"))
    })?;
    let document_path = office_compatible_path(&document_path);
    let before_word_pids = installed_word_process_ids()?;
    let apartment = ComApartment::initialize()?;
    let application = create_word_application()?;
    let process_id = resolve_new_word_process_id(&before_word_pids)?;
    let original_security = application.property_i32("AutomationSecurity")?;
    let original_alerts = application.property_i32("DisplayAlerts")?;
    application.put_bool("Visible", false)?;
    application.put_i32("DisplayAlerts", 0)?;
    application.put_i32("AutomationSecurity", 3)?;
    let result = execute_in_application(&application, process_id, &document_path, operation);
    let _ = application.put_i32("AutomationSecurity", original_security);
    let _ = application.put_i32("DisplayAlerts", original_alerts);
    let _ = application.method("Quit", vec![ComArgument::Boolean(false)]);
    let receipt = result?;
    if before_word_pids.contains(&receipt.word_process_id) {
        return Err(WindowsHostError::new(
            "dedicated Word automation resolved to a pre-existing user process",
        ));
    }
    drop(application);
    drop(apartment);
    wait_for_owned_word_exit(receipt.word_process_id)?;
    Ok(receipt)
}

fn wait_for_owned_word_exit(process_id: u32) -> Result<(), WindowsHostError> {
    for _ in 0..150 {
        if !installed_word_process_ids()?.contains(&process_id) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(WindowsHostError::new(
        "dedicated Word process remained after Quit and COM release",
    ))
}

fn execute_in_application(
    application: &Dispatch,
    process_id: u32,
    document_path: &Path,
    operation: &WordAutomationOperationV1,
) -> Result<WordAutomationReceiptV1, WindowsHostError> {
    let documents = application.property_dispatch("Documents")?;
    let path = document_path.to_string_lossy();
    documents.method("Open", vec![ComArgument::Text(&path)])?;
    let document = application.property_dispatch("ActiveDocument")?;
    let operation_result = apply_operation(&document, operation);
    if operation_result.is_ok() {
        document.method("Save", Vec::new())?;
    }
    let close_result = document.method("Close", vec![ComArgument::Boolean(false)]);
    operation_result?;
    close_result?;
    Ok(WordAutomationReceiptV1 {
        word_process_id: process_id,
        visible: application.property_i32("Visible")? != 0,
        display_alerts: application.property_i32("DisplayAlerts")?,
        automation_security: application.property_i32("AutomationSecurity")?,
        operation_count: 1,
    })
}

fn apply_operation(
    document: &Dispatch,
    operation: &WordAutomationOperationV1,
) -> Result<(), WindowsHostError> {
    match operation {
        WordAutomationOperationV1::AppendParagraph { text } => {
            let content = document.property_dispatch("Content")?;
            content.method("Collapse", vec![ComArgument::Integer(0)])?;
            content.method("InsertAfter", vec![ComArgument::Text(&format!("\r{text}"))])
        }
        WordAutomationOperationV1::InsertTable { cells } => {
            let range = document.property_dispatch("Content")?;
            range.method("Collapse", vec![ComArgument::Integer(0)])?;
            let tables = document.property_dispatch("Tables")?;
            let rows = i32::try_from(cells.len())
                .map_err(|_| WindowsHostError::new("Word table row count overflow"))?;
            let columns = i32::try_from(cells.first().map(Vec::len).unwrap_or_default())
                .map_err(|_| WindowsHostError::new("Word table column count overflow"))?;
            tables.method(
                "Add",
                vec![
                    ComArgument::Dispatch(&range),
                    ComArgument::Integer(rows),
                    ComArgument::Integer(columns),
                ],
            )?;
            let table = tables.method_dispatch(
                "Item",
                vec![ComArgument::Integer(tables.property_i32("Count")?)],
            )?;
            for (row_index, row) in cells.iter().enumerate() {
                for (column_index, text) in row.iter().enumerate() {
                    let cell = table.method_dispatch(
                        "Cell",
                        vec![
                            ComArgument::Integer(index_to_word(row_index)?),
                            ComArgument::Integer(index_to_word(column_index)?),
                        ],
                    )?;
                    cell.property_dispatch("Range")?.put_text("Text", text)?;
                }
            }
            Ok(())
        }
        WordAutomationOperationV1::InsertImage { image_path } => {
            let image_path = image_path.canonicalize().map_err(|error| {
                WindowsHostError::new(format!("image path canonicalization failed: {error}"))
            })?;
            let image_path = office_compatible_path(&image_path);
            let image_text = image_path.to_string_lossy();
            let range = document.property_dispatch("Content")?;
            range.method("Collapse", vec![ComArgument::Integer(0)])?;
            let shapes = document.property_dispatch("InlineShapes")?;
            shapes.method(
                "AddPicture",
                vec![
                    ComArgument::Text(&image_text),
                    ComArgument::Boolean(false),
                    ComArgument::Boolean(true),
                    ComArgument::Dispatch(&range),
                ],
            )?;
            if shapes.property_i32("Count")? <= 0 {
                return Err(WindowsHostError::new(
                    "Word did not retain the embedded image",
                ));
            }
            Ok(())
        }
    }
}

fn validate_operation(operation: &WordAutomationOperationV1) -> Result<(), WindowsHostError> {
    let validate_text = |text: &str| {
        if text.is_empty() || text.chars().count() > 8_192 || text.contains('\0') {
            Err(WindowsHostError::new(
                "Word operation text exceeds its bound",
            ))
        } else {
            Ok(())
        }
    };
    match operation {
        WordAutomationOperationV1::AppendParagraph { text } => validate_text(text),
        WordAutomationOperationV1::InsertTable { cells } => {
            let columns = cells.first().map(Vec::len).unwrap_or_default();
            if cells.is_empty()
                || cells.len() > 256
                || columns == 0
                || columns > 64
                || cells.iter().any(|row| row.len() != columns)
            {
                return Err(WindowsHostError::new("Word table dimensions are invalid"));
            }
            for text in cells.iter().flatten() {
                validate_text(text)?;
            }
            Ok(())
        }
        WordAutomationOperationV1::InsertImage { image_path } => {
            if !image_path.is_file() {
                return Err(WindowsHostError::new("Word image path is not a file"));
            }
            Ok(())
        }
    }
}

fn index_to_word(index: usize) -> Result<i32, WindowsHostError> {
    i32::try_from(index.saturating_add(1))
        .map_err(|_| WindowsHostError::new("Word collection index overflow"))
}

fn office_compatible_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text))
}

fn create_word_application() -> Result<Dispatch, WindowsHostError> {
    let mut pointer = null_mut();
    // SAFETY: CLSID/IID are fixed and the output pointer is initialized by COM.
    let status = unsafe {
        CoCreateInstance(
            &CLSID_WORD_APPLICATION,
            null_mut(),
            CLSCTX_LOCAL_SERVER,
            &IID_IDISPATCH,
            &raw mut pointer,
        )
    };
    check_status(status, "CoCreateInstance(Word.Application)")?;
    if pointer.is_null() {
        return Err(WindowsHostError::new("Word returned a null IDispatch"));
    }
    Ok(Dispatch(pointer.cast()))
}

fn resolve_new_word_process_id(before: &[u32]) -> Result<u32, WindowsHostError> {
    for _ in 0..100 {
        let new_processes = installed_word_process_ids()?
            .into_iter()
            .filter(|process_id| !before.contains(process_id))
            .collect::<Vec<_>>();
        match new_processes.as_slice() {
            [process_id] => return Ok(*process_id),
            [] => std::thread::sleep(std::time::Duration::from_millis(50)),
            _ => {
                return Err(WindowsHostError::new(
                    "Word automation created more than one unbound process",
                ))
            }
        }
    }
    Err(WindowsHostError::new(
        "dedicated Word process was not observed after CoCreateInstance",
    ))
}

pub fn installed_word_process_ids() -> Result<Vec<u32>, WindowsHostError> {
    // SAFETY: a read-only kernel process snapshot is requested.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|error| WindowsHostError::new(format!("process snapshot failed: {error}")))?;
    let snapshot = OwnedSnapshot(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>())
            .map_err(|_| WindowsHostError::new("process entry size overflow"))?,
        ..Default::default()
    };
    // SAFETY: snapshot is live and the entry carries the documented size.
    if unsafe { Process32FirstW(snapshot.0, &raw mut entry) }.is_err() {
        return Ok(Vec::new());
    }
    let mut process_ids = Vec::new();
    loop {
        let length = entry
            .szExeFile
            .iter()
            .position(|character| *character == 0)
            .unwrap_or(entry.szExeFile.len());
        let executable = String::from_utf16_lossy(&entry.szExeFile[..length]);
        if executable.eq_ignore_ascii_case("WINWORD.EXE") {
            process_ids.push(entry.th32ProcessID);
        }
        // SAFETY: snapshot and entry remain valid for this read-only iteration.
        if unsafe { Process32NextW(snapshot.0, &raw mut entry) }.is_err() {
            break;
        }
    }
    Ok(process_ids)
}

struct OwnedSnapshot(HANDLE);

impl Drop for OwnedSnapshot {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this wrapper and closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct ComApartment;

impl ComApartment {
    fn initialize() -> Result<Self, WindowsHostError> {
        // SAFETY: this initializes COM once for the current worker thread.
        let status = unsafe { CoInitializeEx(null_mut(), COINIT_APARTMENTTHREADED) };
        if status < S_OK {
            return Err(WindowsHostError::new(format!(
                "CoInitializeEx failed with HRESULT 0x{:08x}",
                status as u32
            )));
        }
        Ok(Self)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: paired with the successful CoInitializeEx in this thread.
        unsafe { CoUninitialize() };
    }
}

fn check_status(status: i32, operation: &str) -> Result<(), WindowsHostError> {
    if status < S_OK {
        Err(WindowsHostError::new(format!(
            "{operation} failed with HRESULT 0x{:08x}",
            status as u32
        )))
    } else {
        Ok(())
    }
}

#[link(name = "ole32")]
extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, mode: u32) -> i32;
    fn CoUninitialize();
    fn CoCreateInstance(
        class_id: *const Guid,
        outer: *mut c_void,
        context: u32,
        interface_id: *const Guid,
        object: *mut *mut c_void,
    ) -> i32;
}

#[link(name = "oleaut32")]
extern "system" {
    fn SysAllocStringLen(source: *const u16, length: u32) -> *mut u16;
    fn SysFreeString(value: *mut u16);
    fn VariantClear(value: *mut c_void) -> i32;
}
