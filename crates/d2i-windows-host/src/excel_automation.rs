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
const VT_R8: u16 = 5;
const VT_BSTR: u16 = 8;
const VT_ERROR: u16 = 10;
const VT_DISPATCH: u16 = 9;
const VT_BOOL: u16 = 11;
const VARIANT_TRUE: i16 = -1;
const DISP_E_PARAMNOTFOUND: i32 = 0x8002_0004_u32 as i32;
const RPC_E_CALL_REJECTED: i32 = 0x8001_0001_u32 as i32;
const RPC_E_SERVERCALL_RETRYLATER: i32 = 0x8001_010a_u32 as i32;
const MAX_EXCEL_BUSY_RETRIES: u32 = 20;
const EXCEL_BUSY_RETRY_MILLISECONDS: u64 = 100;

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
const CLSID_EXCEL_APPLICATION: Guid = Guid {
    data1: 0x0002_4500,
    data2: 0,
    data3: 0,
    data4: [0xc0, 0, 0, 0, 0, 0, 0, 0x46],
};

#[repr(C)]
union VariantData {
    int_value: i32,
    double_value: f64,
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
        // SAFETY: these fields are null or BSTRs allocated by COM for this Invoke call.
        unsafe {
            for value in [self.source, self.description, self.help_file] {
                if !value.is_null() {
                    SysFreeString(value);
                }
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
        let mut member_id = 0_i32;
        let mut attempt = 0_u32;
        let status = loop {
            let mut name_pointer = wide.as_mut_ptr();
            // SAFETY: the dispatch pointer and null-terminated member name are valid for this call.
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
            if is_retryable_excel_busy(status) && attempt < MAX_EXCEL_BUSY_RETRIES {
                attempt = attempt.saturating_add(1);
                std::thread::sleep(std::time::Duration::from_millis(
                    EXCEL_BUSY_RETRY_MILLISECONDS,
                ));
                continue;
            }
            break status;
        };
        check_status(status, &format!("Excel GetIDsOfNames({name})"))?;
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
        let property_put = flags == DISPATCH_PROPERTYPUT;
        let mut property_put_id = DISPID_PROPERTYPUT;
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
                .map_err(|_| WindowsHostError::new("Excel COM argument count overflow"))?,
            named_argument_count: u32::from(property_put),
        };
        let mut attempt = 0_u32;
        loop {
            let mut result = Variant::empty();
            let mut exception = ExceptionInfo::empty();
            let mut argument_error = 0_u32;
            // SAFETY: the COM pointer, argument VARIANTs, and DISPPARAMS live for Invoke.
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
            if is_retryable_excel_busy(status) && attempt < MAX_EXCEL_BUSY_RETRIES {
                attempt = attempt.saturating_add(1);
                drop(result);
                std::thread::sleep(std::time::Duration::from_millis(
                    EXCEL_BUSY_RETRY_MILLISECONDS,
                ));
                continue;
            }
            check_status(status, &format!("Excel {name}"))?;
            return Ok(result);
        }
    }

    fn property_dispatch(&self, name: &'static str) -> Result<Dispatch, WindowsHostError> {
        take_dispatch(self.invoke(name, DISPATCH_PROPERTYGET, Vec::new())?, name)
    }

    fn indexed_property_dispatch(
        &self,
        name: &'static str,
        arguments: Vec<ComArgument<'_>>,
    ) -> Result<Dispatch, WindowsHostError> {
        take_dispatch(self.invoke(name, DISPATCH_PROPERTYGET, arguments)?, name)
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
            "Excel property {name} returned an unexpected type"
        )))
    }

    fn put(&self, name: &'static str, value: ComArgument<'_>) -> Result<(), WindowsHostError> {
        self.invoke(name, DISPATCH_PROPERTYPUT, vec![value])?;
        Ok(())
    }

    fn put_i32(&self, name: &'static str, value: i32) -> Result<(), WindowsHostError> {
        self.put(name, ComArgument::Integer(value))
    }

    fn put_bool(&self, name: &'static str, value: bool) -> Result<(), WindowsHostError> {
        self.put(name, ComArgument::Boolean(value))
    }

    fn method(
        &self,
        name: &'static str,
        arguments: Vec<ComArgument<'_>>,
    ) -> Result<(), WindowsHostError> {
        self.invoke(name, DISPATCH_METHOD, arguments)?;
        Ok(())
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
    Missing,
    Integer(i32),
    Double(f64),
    Boolean(bool),
    Text(&'a str),
}

impl ComArgument<'_> {
    fn into_variant(self) -> Result<Variant, WindowsHostError> {
        let mut value = Variant::empty();
        match self {
            Self::Missing => {
                value.variant_type = VT_ERROR;
                value.data.int_value = DISP_E_PARAMNOTFOUND;
            }
            Self::Integer(integer) => {
                value.variant_type = VT_I4;
                value.data.int_value = integer;
            }
            Self::Double(double) => {
                if !double.is_finite() {
                    return Err(WindowsHostError::new("Excel number is not finite"));
                }
                value.variant_type = VT_R8;
                value.data.double_value = double;
            }
            Self::Boolean(boolean) => {
                value.variant_type = VT_BOOL;
                value.data.bool_value = if boolean { VARIANT_TRUE } else { 0 };
            }
            Self::Text(text) => {
                let wide = text.encode_utf16().collect::<Vec<_>>();
                let length = u32::try_from(wide.len())
                    .map_err(|_| WindowsHostError::new("Excel COM text length overflow"))?;
                // SAFETY: SysAllocStringLen copies the supplied UTF-16 buffer.
                let bstr = unsafe { SysAllocStringLen(wide.as_ptr(), length) };
                if bstr.is_null() && !wide.is_empty() {
                    return Err(WindowsHostError::new("Excel BSTR allocation failed"));
                }
                value.variant_type = VT_BSTR;
                value.data.bstr_value = bstr;
            }
        }
        Ok(value)
    }
}

fn take_dispatch(mut value: Variant, label: &str) -> Result<Dispatch, WindowsHostError> {
    if value.variant_type != VT_DISPATCH {
        return Err(WindowsHostError::new(format!(
            "Excel {label} returned VARIANT type {} instead of an automation object",
            value.variant_type
        )));
    }
    // SAFETY: the active VARIANT arm is selected by VT_DISPATCH.
    let pointer = unsafe { value.data.dispatch_value };
    if pointer.is_null() {
        return Err(WindowsHostError::new(format!(
            "Excel {label} returned a null automation object"
        )));
    }
    value.variant_type = VT_EMPTY;
    value.data.padding = [0; 2];
    Ok(Dispatch(pointer))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExcelAutomationScalarV1 {
    Text(String),
    Integer(i32),
    Decimal { scaled_value: i64, scale: u32 },
    Boolean(bool),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExcelAutomationFormulaV1 {
    Sum {
        range: String,
    },
    Difference {
        left: String,
        right: String,
    },
    Product {
        left: String,
        right: String,
    },
    Ratio {
        numerator: String,
        denominator: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExcelAutomationOperationV1 {
    SetCellValue {
        sheet_index: i32,
        cell: String,
        value: ExcelAutomationScalarV1,
    },
    SetCellFormula {
        sheet_index: i32,
        cell: String,
        formula: ExcelAutomationFormulaV1,
    },
    AppendRow {
        sheet_index: i32,
        excel_row: i32,
        values: Vec<(i32, ExcelAutomationScalarV1)>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcelAutomationReceiptV1 {
    pub excel_process_id: u32,
    pub visible: bool,
    pub display_alerts: bool,
    pub automation_security: i32,
    pub enable_events: bool,
    pub ask_to_update_links: bool,
    pub operation_count: u32,
    pub full_recalculation: bool,
    pub forced_process_termination: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcelPdfExportReceiptV1 {
    pub excel_process_id: u32,
    pub visible_sheet_count: u32,
    pub hidden_sheet_count: u32,
    pub private_desktop: bool,
    pub visible: bool,
    pub display_alerts: bool,
    pub automation_security: i32,
    pub enable_events: bool,
    pub ask_to_update_links: bool,
    pub pdfa_requested: bool,
    pub output_fresh_and_stable: bool,
    pub forced_process_termination: bool,
}

pub fn export_excel_workbook_pdf(
    source_path: &Path,
    destination_path: &Path,
    expected_excel_executable: &Path,
    pdfa_requested: bool,
) -> Result<ExcelPdfExportReceiptV1, WindowsHostError> {
    validate_pdf_paths(source_path, destination_path)?;
    let source_path = office_compatible_path(&source_path.canonicalize().map_err(|error| {
        WindowsHostError::new(format!("Excel source canonicalization failed: {error}"))
    })?);
    let destination_path = office_export_output_path(destination_path)?;
    let before_excel_pids = installed_excel_process_ids()?;
    let private_desktop = OfficePrivateDesktop::enter("excel")?;
    let apartment = ComApartment::initialize()?;
    let application = create_excel_application()?;
    let process_id = resolve_new_excel_process_id(&before_excel_pids)?;
    let actual_executable = super::process_image_path(process_id)?;
    if !actual_executable
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected_excel_executable.to_string_lossy())
    {
        let _ = application.method("Quit", Vec::new());
        return Err(WindowsHostError::new(
            "dedicated Excel PDF exporter differs from its binding",
        ));
    }
    let original_security = application.property_i32("AutomationSecurity")?;
    let original_alerts = application.property_i32("DisplayAlerts")? != 0;
    let original_events = application.property_i32("EnableEvents")? != 0;
    let original_update_links = application.property_i32("AskToUpdateLinks")? != 0;
    application.put_bool("Visible", false)?;
    application.put_bool("DisplayAlerts", false)?;
    application.put_bool("EnableEvents", false)?;
    application.put_bool("AskToUpdateLinks", false)?;
    application.put_i32("AutomationSecurity", 3)?;
    let result = (|| {
        let workbooks = application.property_dispatch("Workbooks")?;
        let source = source_path.to_string_lossy();
        let workbook = workbooks.method_dispatch(
            "Open",
            vec![
                ComArgument::Text(&source),
                ComArgument::Integer(0),
                ComArgument::Boolean(true),
            ],
        )?;
        let worksheets = workbook.property_dispatch("Worksheets")?;
        let count = worksheets.property_i32("Count")?;
        if count <= 0 || count > 256 {
            return Err(WindowsHostError::new("Excel sheet count exceeds bounds"));
        }
        let mut visible = 0_u32;
        let mut hidden = 0_u32;
        for index in 1..=count {
            let sheet =
                worksheets.indexed_property_dispatch("Item", vec![ComArgument::Integer(index)])?;
            if sheet.property_i32("Visible")? == -1 {
                visible = visible.saturating_add(1);
            } else {
                hidden = hidden.saturating_add(1);
            }
        }
        if visible == 0 {
            return Err(WindowsHostError::new("Excel workbook has no visible sheet"));
        }
        let destination = destination_path.to_string_lossy();
        let export = workbook.method(
            "ExportAsFixedFormat",
            vec![
                ComArgument::Integer(0),
                ComArgument::Text(&destination),
                ComArgument::Integer(0),
                ComArgument::Boolean(true),
                ComArgument::Boolean(false),
                ComArgument::Missing,
                ComArgument::Missing,
                ComArgument::Boolean(false),
            ],
        );
        let close = workbook.method("Close", vec![ComArgument::Boolean(false)]);
        export?;
        close?;
        Ok((visible, hidden))
    })();
    let _ = application.put_i32("AutomationSecurity", original_security);
    let _ = application.put_bool("DisplayAlerts", original_alerts);
    let _ = application.put_bool("EnableEvents", original_events);
    let _ = application.put_bool("AskToUpdateLinks", original_update_links);
    let _ = application.method("Quit", Vec::new());
    drop(application);
    drop(apartment);
    let forced_process_termination =
        wait_for_owned_excel_exit(process_id, expected_excel_executable)?;
    private_desktop.leave()?;
    let (visible_sheet_count, hidden_sheet_count) = result?;
    wait_for_stable_pdf(&destination_path)?;
    Ok(ExcelPdfExportReceiptV1 {
        excel_process_id: process_id,
        visible_sheet_count,
        hidden_sheet_count,
        private_desktop: true,
        visible: false,
        display_alerts: false,
        automation_security: 3,
        enable_events: false,
        ask_to_update_links: false,
        pdfa_requested,
        output_fresh_and_stable: true,
        forced_process_termination,
    })
}

fn validate_pdf_paths(source_path: &Path, destination_path: &Path) -> Result<(), WindowsHostError> {
    if !source_path.is_file()
        || destination_path.exists()
        || source_path == destination_path
        || !source_path
            .extension()
            .is_some_and(|value| value.eq_ignore_ascii_case("xlsx"))
        || !destination_path
            .extension()
            .is_some_and(|value| value.eq_ignore_ascii_case("pdf"))
        || !destination_path.parent().is_some_and(Path::is_dir)
    {
        return Err(WindowsHostError::new("Excel PDF export paths are invalid"));
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
                    WindowsHostError::new(format!("Excel PDF read failed: {error}"))
                })?;
                if header.starts_with(b"%PDF-") {
                    return Ok(());
                }
                return Err(WindowsHostError::new("Excel output is not a PDF"));
            }
        } else {
            stable = 0;
        }
        previous = size;
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(WindowsHostError::new(
        "Excel PDF output did not become stable",
    ))
}

pub fn execute_excel_spreadsheet_operation(
    workbook_path: &Path,
    expected_excel_executable: &Path,
    operation: &ExcelAutomationOperationV1,
) -> Result<ExcelAutomationReceiptV1, WindowsHostError> {
    if !workbook_path.is_file() {
        return Err(WindowsHostError::new("Excel workbook path is not a file"));
    }
    validate_operation(operation)?;
    let workbook_path = workbook_path.canonicalize().map_err(|error| {
        WindowsHostError::new(format!("Excel workbook canonicalization failed: {error}"))
    })?;
    let workbook_path = office_compatible_path(&workbook_path);
    let before_excel_pids = installed_excel_process_ids()?;
    let apartment = ComApartment::initialize()?;
    let application = create_excel_application()?;
    let process_id = resolve_new_excel_process_id(&before_excel_pids)?;
    let actual_executable = super::process_image_path(process_id)?;
    if !actual_executable
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected_excel_executable.to_string_lossy())
    {
        let _ = application.method("Quit", Vec::new());
        return Err(WindowsHostError::new(
            "dedicated Excel process executable differs from its binding",
        ));
    }
    let original_security = application.property_i32("AutomationSecurity")?;
    let original_alerts = application.property_i32("DisplayAlerts")? != 0;
    let original_events = application.property_i32("EnableEvents")? != 0;
    let original_update_links = application.property_i32("AskToUpdateLinks")? != 0;
    application.put_bool("Visible", false)?;
    application.put_bool("DisplayAlerts", false)?;
    application.put_bool("EnableEvents", false)?;
    application.put_bool("AskToUpdateLinks", false)?;
    application.put_i32("AutomationSecurity", 3)?;
    let result = execute_in_application(&application, process_id, &workbook_path, operation);
    let _ = application.put_i32("AutomationSecurity", original_security);
    let _ = application.put_bool("DisplayAlerts", original_alerts);
    let _ = application.put_bool("EnableEvents", original_events);
    let _ = application.put_bool("AskToUpdateLinks", original_update_links);
    let _ = application.method("Quit", Vec::new());
    if before_excel_pids.contains(&process_id) {
        return Err(WindowsHostError::new(
            "dedicated Excel automation resolved to a pre-existing user process",
        ));
    }
    drop(application);
    drop(apartment);
    let forced_process_termination =
        wait_for_owned_excel_exit(process_id, expected_excel_executable)?;
    let mut receipt = result?;
    receipt.forced_process_termination = forced_process_termination;
    Ok(receipt)
}

fn execute_in_application(
    application: &Dispatch,
    process_id: u32,
    workbook_path: &Path,
    operation: &ExcelAutomationOperationV1,
) -> Result<ExcelAutomationReceiptV1, WindowsHostError> {
    let workbooks = application.property_dispatch("Workbooks")?;
    let path = workbook_path.to_string_lossy();
    let workbook = workbooks.method_dispatch(
        "Open",
        vec![
            ComArgument::Text(&path),
            ComArgument::Integer(0),
            ComArgument::Boolean(false),
        ],
    )?;
    let operation_result = apply_operation(&workbook, operation);
    let calculation_result = if operation_result.is_ok() {
        application.method("CalculateFullRebuild", Vec::new())
    } else {
        Ok(())
    };
    if operation_result.is_ok() && calculation_result.is_ok() {
        workbook.method("Save", Vec::new())?;
    }
    let close_result = workbook.method("Close", vec![ComArgument::Boolean(false)]);
    operation_result?;
    calculation_result?;
    close_result?;
    Ok(ExcelAutomationReceiptV1 {
        excel_process_id: process_id,
        visible: application.property_i32("Visible")? != 0,
        display_alerts: application.property_i32("DisplayAlerts")? != 0,
        automation_security: application.property_i32("AutomationSecurity")?,
        enable_events: application.property_i32("EnableEvents")? != 0,
        ask_to_update_links: application.property_i32("AskToUpdateLinks")? != 0,
        operation_count: 1,
        full_recalculation: true,
        forced_process_termination: false,
    })
}

fn apply_operation(
    workbook: &Dispatch,
    operation: &ExcelAutomationOperationV1,
) -> Result<(), WindowsHostError> {
    let worksheets = workbook.property_dispatch("Worksheets")?;
    match operation {
        ExcelAutomationOperationV1::SetCellValue {
            sheet_index,
            cell,
            value,
        } => {
            let sheet = worksheets
                .indexed_property_dispatch("Item", vec![ComArgument::Integer(*sheet_index)])?;
            let range = sheet.indexed_property_dispatch("Range", vec![ComArgument::Text(cell)])?;
            range.put("Value2", scalar_argument(value)?)
        }
        ExcelAutomationOperationV1::SetCellFormula {
            sheet_index,
            cell,
            formula,
        } => {
            let sheet = worksheets
                .indexed_property_dispatch("Item", vec![ComArgument::Integer(*sheet_index)])?;
            let range = sheet.indexed_property_dispatch("Range", vec![ComArgument::Text(cell)])?;
            let formula = render_formula(formula)?;
            range.put("Formula", ComArgument::Text(&formula))
        }
        ExcelAutomationOperationV1::AppendRow {
            sheet_index,
            excel_row,
            values,
        } => {
            let sheet = worksheets
                .indexed_property_dispatch("Item", vec![ComArgument::Integer(*sheet_index)])?;
            for (column, value) in values {
                let cell = a1_reference(*column, *excel_row)?;
                let range =
                    sheet.indexed_property_dispatch("Range", vec![ComArgument::Text(&cell)])?;
                range.put("Value2", scalar_argument(value)?)?;
            }
            Ok(())
        }
    }
}

fn scalar_argument(value: &ExcelAutomationScalarV1) -> Result<ComArgument<'_>, WindowsHostError> {
    match value {
        ExcelAutomationScalarV1::Text(text) => Ok(ComArgument::Text(text)),
        ExcelAutomationScalarV1::Integer(integer) => Ok(ComArgument::Integer(*integer)),
        ExcelAutomationScalarV1::Decimal {
            scaled_value,
            scale,
        } => {
            if *scale > 6 {
                return Err(WindowsHostError::new("Excel decimal scale exceeds six"));
            }
            let divisor = 10_f64.powi(
                i32::try_from(*scale)
                    .map_err(|_| WindowsHostError::new("Excel decimal scale overflows"))?,
            );
            Ok(ComArgument::Double(*scaled_value as f64 / divisor))
        }
        ExcelAutomationScalarV1::Boolean(boolean) => Ok(ComArgument::Boolean(*boolean)),
    }
}

fn render_formula(formula: &ExcelAutomationFormulaV1) -> Result<String, WindowsHostError> {
    let rendered = match formula {
        ExcelAutomationFormulaV1::Sum { range } => {
            validate_range_reference(range)?;
            format!("=SUM({range})")
        }
        ExcelAutomationFormulaV1::Difference { left, right } => {
            validate_cell_reference(left)?;
            validate_cell_reference(right)?;
            format!("={left}-{right}")
        }
        ExcelAutomationFormulaV1::Product { left, right } => {
            validate_cell_reference(left)?;
            validate_cell_reference(right)?;
            format!("={left}*{right}")
        }
        ExcelAutomationFormulaV1::Ratio {
            numerator,
            denominator,
        } => {
            validate_cell_reference(numerator)?;
            validate_cell_reference(denominator)?;
            format!("={numerator}/{denominator}")
        }
    };
    if rendered.len() > 128 {
        return Err(WindowsHostError::new(
            "Excel fixed formula exceeds its bound",
        ));
    }
    Ok(rendered)
}

fn validate_operation(operation: &ExcelAutomationOperationV1) -> Result<(), WindowsHostError> {
    let validate_scalar = |value: &ExcelAutomationScalarV1| match value {
        ExcelAutomationScalarV1::Text(text)
            if text.is_empty() || text.chars().count() > 512 || text.contains('\0') =>
        {
            Err(WindowsHostError::new("Excel text exceeds its bound"))
        }
        ExcelAutomationScalarV1::Decimal { scale, .. } if *scale > 6 => {
            Err(WindowsHostError::new("Excel decimal scale exceeds six"))
        }
        _ => Ok(()),
    };
    match operation {
        ExcelAutomationOperationV1::SetCellValue {
            sheet_index,
            cell,
            value,
        } => {
            validate_sheet_index(*sheet_index)?;
            validate_cell_reference(cell)?;
            validate_scalar(value)
        }
        ExcelAutomationOperationV1::SetCellFormula {
            sheet_index,
            cell,
            formula,
        } => {
            validate_sheet_index(*sheet_index)?;
            validate_cell_reference(cell)?;
            render_formula(formula).map(|_| ())
        }
        ExcelAutomationOperationV1::AppendRow {
            sheet_index,
            excel_row,
            values,
        } => {
            validate_sheet_index(*sheet_index)?;
            if *excel_row < 2 || *excel_row > 1_048_576 || values.is_empty() || values.len() > 1_024
            {
                return Err(WindowsHostError::new("Excel append dimensions are invalid"));
            }
            let mut previous = 0_i32;
            for (column, value) in values {
                if *column <= previous || *column > 16_384 {
                    return Err(WindowsHostError::new(
                        "Excel append columns are unordered or invalid",
                    ));
                }
                previous = *column;
                validate_scalar(value)?;
            }
            Ok(())
        }
    }
}

fn validate_sheet_index(index: i32) -> Result<(), WindowsHostError> {
    if index <= 0 || index > 256 {
        Err(WindowsHostError::new("Excel sheet index is invalid"))
    } else {
        Ok(())
    }
}

fn validate_cell_reference(value: &str) -> Result<(), WindowsHostError> {
    if value.is_empty()
        || value.len() > 12
        || value.contains(['$', ':', '!', '[', ']', '\'', '"'])
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || !value.bytes().any(|byte| byte.is_ascii_digit())
        || !value.bytes().any(|byte| byte.is_ascii_alphabetic())
    {
        return Err(WindowsHostError::new("Excel A1 reference is invalid"));
    }
    Ok(())
}

fn validate_range_reference(value: &str) -> Result<(), WindowsHostError> {
    let (start, end) = value
        .split_once(':')
        .ok_or_else(|| WindowsHostError::new("Excel range reference is invalid"))?;
    validate_cell_reference(start)?;
    validate_cell_reference(end)
}

fn a1_reference(column: i32, row: i32) -> Result<String, WindowsHostError> {
    if column <= 0 || column > 16_384 || row <= 0 || row > 1_048_576 {
        return Err(WindowsHostError::new(
            "Excel coordinate exceeds format bounds",
        ));
    }
    let mut value = u32::try_from(column)
        .map_err(|_| WindowsHostError::new("Excel column conversion failed"))?;
    let mut letters = Vec::new();
    while value > 0 {
        value -= 1;
        letters.push(
            char::from_u32(u32::from(b'A') + value % 26)
                .ok_or_else(|| WindowsHostError::new("Excel column conversion failed"))?,
        );
        value /= 26;
    }
    letters.reverse();
    Ok(format!("{}{row}", letters.into_iter().collect::<String>()))
}

fn create_excel_application() -> Result<Dispatch, WindowsHostError> {
    let mut pointer = null_mut();
    // SAFETY: CLSID/IID are fixed and COM initializes the output pointer.
    let status = unsafe {
        CoCreateInstance(
            &CLSID_EXCEL_APPLICATION,
            null_mut(),
            CLSCTX_LOCAL_SERVER,
            &IID_IDISPATCH,
            &raw mut pointer,
        )
    };
    check_status(status, "CoCreateInstance(Excel.Application)")?;
    if pointer.is_null() {
        return Err(WindowsHostError::new("Excel returned a null IDispatch"));
    }
    Ok(Dispatch(pointer.cast()))
}

fn resolve_new_excel_process_id(before: &[u32]) -> Result<u32, WindowsHostError> {
    for _ in 0..100 {
        let new_processes = installed_excel_process_ids()?
            .into_iter()
            .filter(|process_id| !before.contains(process_id))
            .collect::<Vec<_>>();
        match new_processes.as_slice() {
            [process_id] => return Ok(*process_id),
            [] => std::thread::sleep(std::time::Duration::from_millis(50)),
            _ => {
                return Err(WindowsHostError::new(
                    "Excel automation created more than one unbound process",
                ))
            }
        }
    }
    Err(WindowsHostError::new(
        "dedicated Excel process was not observed after CoCreateInstance",
    ))
}

fn wait_for_owned_excel_exit(
    process_id: u32,
    expected_excel_executable: &Path,
) -> Result<bool, WindowsHostError> {
    for _ in 0..30 {
        if !installed_excel_process_ids()?.contains(&process_id) {
            return Ok(false);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    super::terminate_process_if_exact_image(process_id, expected_excel_executable)?;
    if installed_excel_process_ids()?.contains(&process_id) {
        return Err(WindowsHostError::new(
            "exact worker-owned Excel process remained after bounded termination",
        ));
    }
    Ok(true)
}

pub fn installed_excel_process_ids() -> Result<Vec<u32>, WindowsHostError> {
    // SAFETY: a read-only process snapshot is requested.
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
        if executable.eq_ignore_ascii_case("EXCEL.EXE") {
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
        // SAFETY: this wrapper owns the snapshot handle and closes it once.
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

fn office_compatible_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text))
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

fn is_retryable_excel_busy(status: i32) -> bool {
    matches!(status, RPC_E_CALL_REJECTED | RPC_E_SERVERCALL_RETRYLATER)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formula_contract_has_no_raw_formula_variant() {
        let fixed = ExcelAutomationFormulaV1::Ratio {
            numerator: "B2".to_owned(),
            denominator: "C2".to_owned(),
        };
        assert_eq!(
            render_formula(&fixed)
                .unwrap_or_else(|error| panic!("fixed formula must render: {error}")),
            "=B2/C2"
        );
        assert!(validate_cell_reference("[book.xlsx]A1").is_err());
        assert!(validate_range_reference("A1:https://example.test").is_err());
    }

    #[test]
    fn only_explicit_excel_busy_hresult_values_are_retryable() {
        assert!(is_retryable_excel_busy(RPC_E_CALL_REJECTED));
        assert!(is_retryable_excel_busy(RPC_E_SERVERCALL_RETRYLATER));
        assert!(!is_retryable_excel_busy(0x8000_4005_u32 as i32));
        assert!(!is_retryable_excel_busy(S_OK));
    }
}
