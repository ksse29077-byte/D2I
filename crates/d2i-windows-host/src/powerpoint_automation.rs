use super::WindowsHostError;
use crate::office_private_desktop::office_export_output_path;
use std::ffi::c_void;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CreateDesktopW, GetThreadDesktop, SetThreadDesktop, DESKTOP_CONTROL_FLAGS,
    DESKTOP_CREATEWINDOW, DESKTOP_ENUMERATE, DESKTOP_READOBJECTS, DESKTOP_WRITEOBJECTS, HDESK,
};
use windows::Win32::System::Threading::GetCurrentThreadId;

const S_OK: i32 = 0;
const COINIT_APARTMENTTHREADED: u32 = 0x2;
const CLSCTX_LOCAL_SERVER: u32 = 0x4;
const DISPATCH_METHOD: u16 = 0x1;
const DISPATCH_PROPERTYGET: u16 = 0x2;
const DISPATCH_PROPERTYPUT: u16 = 0x4;
const DISPID_PROPERTYPUT: i32 = -3;
const VT_EMPTY: u16 = 0;
const VT_I4: u16 = 3;
const VT_R4: u16 = 4;
const VT_R8: u16 = 5;
const VT_BSTR: u16 = 8;
const VT_ERROR: u16 = 10;
const VT_DISPATCH: u16 = 9;
const VT_BOOL: u16 = 11;
const VT_VARIANT: u16 = 12;
const VT_ARRAY: u16 = 0x2000;
const VARIANT_TRUE: i16 = -1;
const DISP_E_PARAMNOTFOUND: i32 = 0x8002_0004_u32 as i32;

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
const CLSID_POWERPOINT_APPLICATION: Guid = Guid {
    data1: 0x9149_3441,
    data2: 0x5a91,
    data3: 0x11cf,
    data4: [0x87, 0, 0, 0xaa, 0, 0x60, 0x26, 0x3b],
};

#[repr(C)]
union VariantData {
    int_value: i32,
    float_value: f32,
    double_value: f64,
    bool_value: i16,
    bstr_value: *mut u16,
    dispatch_value: *mut RawDispatch,
    array_value: *mut SafeArray,
    padding: [u64; 2],
}

#[repr(C)]
struct SafeArray {
    _private: [u8; 0],
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

    fn description(&self) -> String {
        if self.description.is_null() {
            return String::new();
        }
        // SAFETY: description is a live BSTR until clear releases it.
        let length = unsafe { SysStringLen(self.description) } as usize;
        // SAFETY: a BSTR points to at least SysStringLen UTF-16 code units.
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(self.description, length) })
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
        let exception_description = exception.description();
        exception.clear();
        let diagnostic = if status == S_OK {
            name.to_owned()
        } else {
            format!(
                "{name} (reversed COM argument index {argument_error}, exception {exception_description})"
            )
        };
        check_status(status, &diagnostic)?;
        Ok(result)
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
            "PowerPoint property {name} returned an unexpected type"
        )))
    }

    fn property_points_i32(&self, name: &'static str) -> Result<i32, WindowsHostError> {
        let result = self.invoke(name, DISPATCH_PROPERTYGET, Vec::new())?;
        // SAFETY: each union arm is selected only after checking its VARIANT type tag.
        let points = unsafe {
            match result.variant_type {
                VT_I4 => f64::from(result.data.int_value),
                VT_R4 => f64::from(result.data.float_value),
                VT_R8 => result.data.double_value,
                _ => {
                    return Err(WindowsHostError::new(format!(
                        "PowerPoint dimension {name} returned an unexpected type"
                    )))
                }
            }
        };
        if !points.is_finite() || !(240.0..=2_000.0).contains(&points) {
            return Err(WindowsHostError::new(format!(
                "PowerPoint dimension {name} exceeds bounds"
            )));
        }
        Ok(points.round() as i32)
    }

    fn put_i32(&self, name: &'static str, value: i32) -> Result<(), WindowsHostError> {
        self.invoke(
            name,
            DISPATCH_PROPERTYPUT,
            vec![ComArgument::Integer(value)],
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
    NullDispatch,
    Integer(i32),
    Boolean(bool),
    Text(&'a str),
    IntegerArray(&'a [i32]),
    TextArray(&'a [String]),
}

impl ComArgument<'_> {
    fn into_variant(self) -> Result<Variant, WindowsHostError> {
        let mut value = Variant::empty();
        match self {
            Self::Missing => {
                value.variant_type = VT_ERROR;
                value.data.int_value = DISP_E_PARAMNOTFOUND;
            }
            Self::NullDispatch => {
                value.variant_type = VT_DISPATCH;
                value.data.dispatch_value = null_mut();
            }
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
            Self::IntegerArray(values) => return integer_array_variant(values),
            Self::TextArray(values) => return text_array_variant(values),
        }
        Ok(value)
    }
}

fn integer_array_variant(values: &[i32]) -> Result<Variant, WindowsHostError> {
    let mut array = create_variant_array(values.len())?;
    for (index, integer) in values.iter().enumerate() {
        let element = ComArgument::Integer(*integer).into_variant()?;
        put_array_element(&mut array, index, &element)?;
    }
    Ok(array)
}

fn text_array_variant(values: &[String]) -> Result<Variant, WindowsHostError> {
    let mut array = create_variant_array(values.len())?;
    for (index, text) in values.iter().enumerate() {
        let element = ComArgument::Text(text).into_variant()?;
        put_array_element(&mut array, index, &element)?;
    }
    Ok(array)
}

fn create_variant_array(length: usize) -> Result<Variant, WindowsHostError> {
    let count =
        u32::try_from(length).map_err(|_| WindowsHostError::new("COM array length overflow"))?;
    if count == 0 || count > 16 {
        return Err(WindowsHostError::new("COM array length exceeds bounds"));
    }
    // SAFETY: SafeArrayCreateVector creates an owned one-dimensional array.
    let array = unsafe { SafeArrayCreateVector(VT_VARIANT, 0, count) };
    if array.is_null() {
        return Err(WindowsHostError::new("SAFEARRAY allocation failed"));
    }
    let mut value = Variant::empty();
    value.variant_type = VT_ARRAY | VT_VARIANT;
    value.data.array_value = array;
    Ok(value)
}

fn put_array_element(
    array: &mut Variant,
    index: usize,
    element: &Variant,
) -> Result<(), WindowsHostError> {
    let mut index =
        i32::try_from(index).map_err(|_| WindowsHostError::new("COM array index overflow"))?;
    // SAFETY: array owns a VT_VARIANT SAFEARRAY and element points to a valid VARIANT
    // that SafeArrayPutElement copies into the requested in-bounds slot.
    let status = unsafe {
        SafeArrayPutElement(
            array.data.array_value,
            &raw mut index,
            (element as *const Variant).cast_mut().cast(),
        )
    };
    check_status(status, "SafeArrayPutElement")
}

fn take_dispatch(mut value: Variant, label: &str) -> Result<Dispatch, WindowsHostError> {
    if value.variant_type != VT_DISPATCH {
        return Err(WindowsHostError::new(format!(
            "PowerPoint {label} returned VARIANT type {} instead of an automation object",
            value.variant_type
        )));
    }
    // SAFETY: the active VARIANT arm is selected by VT_DISPATCH.
    let pointer = unsafe { value.data.dispatch_value };
    if pointer.is_null() {
        return Err(WindowsHostError::new(format!(
            "PowerPoint {label} returned a null automation object"
        )));
    }
    value.variant_type = VT_EMPTY;
    value.data.padding = [0; 2];
    Ok(Dispatch(pointer))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowerPointAutomationOperationV1 {
    AddSlide {
        title: String,
        body: String,
    },
    SetText {
        slide_index: i32,
        shape_name: String,
        text: String,
    },
    InsertTable {
        slide_index: i32,
        shape_name: String,
        cells: Vec<Vec<String>>,
    },
    InsertImage {
        slide_index: i32,
        shape_name: String,
        image_path: PathBuf,
    },
    InsertChart {
        slide_index: i32,
        shape_name: String,
        chart_type: i32,
        categories: Vec<String>,
        values: Vec<i32>,
    },
}

struct PrivateDesktop {
    original: HDESK,
    private: HDESK,
    active: bool,
}

impl PrivateDesktop {
    fn enter() -> Result<Self, WindowsHostError> {
        let name = format!("d2i-office400-powerpoint-{}", std::process::id());
        let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        // SAFETY: GetCurrentThreadId has no preconditions and returns the calling thread ID.
        let original = unsafe { GetThreadDesktop(GetCurrentThreadId()) }.map_err(|error| {
            WindowsHostError::new(format!(
                "PowerPoint original desktop lookup failed: {error}"
            ))
        })?;
        let access = DESKTOP_CREATEWINDOW.0
            | DESKTOP_ENUMERATE.0
            | DESKTOP_READOBJECTS.0
            | DESKTOP_WRITEOBJECTS.0;
        // SAFETY: the desktop name is null-terminated, device and security attributes are absent,
        // and the returned handle is owned until CloseDesktop.
        let private = unsafe {
            CreateDesktopW(
                PCWSTR(name.as_ptr()),
                PCWSTR::null(),
                None,
                DESKTOP_CONTROL_FLAGS(0),
                access,
                None,
            )
        }
        .map_err(|error| {
            WindowsHostError::new(format!(
                "PowerPoint private desktop creation failed: {error}"
            ))
        })?;
        // SAFETY: private is a valid desktop handle and this worker thread has not created windows.
        if let Err(error) = unsafe { SetThreadDesktop(private) } {
            // SAFETY: private remains owned here because assignment failed.
            let _ = unsafe { CloseDesktop(private) };
            return Err(WindowsHostError::new(format!(
                "PowerPoint private desktop assignment failed: {error}"
            )));
        }
        Ok(Self {
            original,
            private,
            active: true,
        })
    }

    fn leave(mut self) -> Result<(), WindowsHostError> {
        self.release()
    }

    fn release(&mut self) -> Result<(), WindowsHostError> {
        if !self.active {
            return Ok(());
        }
        // SAFETY: original is the borrowed desktop handle captured before this thread switched.
        unsafe { SetThreadDesktop(self.original) }.map_err(|error| {
            WindowsHostError::new(format!("PowerPoint desktop restore failed: {error}"))
        })?;
        // SAFETY: the thread no longer uses private and this object owns its handle.
        unsafe { CloseDesktop(self.private) }.map_err(|error| {
            WindowsHostError::new(format!(
                "PowerPoint private desktop cleanup failed: {error}"
            ))
        })?;
        self.active = false;
        Ok(())
    }
}

impl Drop for PrivateDesktop {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerPointAutomationReceiptV1 {
    pub powerpoint_process_id: u32,
    pub powerpoint_image_path: PathBuf,
    pub chart_excel_process_id: Option<u32>,
    pub chart_excel_process_ids: Vec<u32>,
    pub forced_excel_process_termination: bool,
    pub visible: bool,
    pub application_visible_on_private_desktop: bool,
    pub private_desktop: bool,
    pub display_alerts: i32,
    pub automation_security: i32,
    pub operation_count: u32,
    pub rendered_slide_count: u32,
    pub text_overflow_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerPointPdfExportReceiptV1 {
    pub powerpoint_process_id: u32,
    pub powerpoint_image_path: PathBuf,
    pub visible_slide_count: u32,
    pub hidden_slide_count: u32,
    pub private_desktop: bool,
    pub application_visible_on_private_desktop: bool,
    pub display_alerts: i32,
    pub automation_security: i32,
    pub pdfa_requested: bool,
    pub output_fresh_and_stable: bool,
}

pub fn export_powerpoint_presentation_pdf(
    source_path: &Path,
    destination_path: &Path,
    pdfa_requested: bool,
) -> Result<PowerPointPdfExportReceiptV1, WindowsHostError> {
    validate_pdf_paths(source_path, destination_path)?;
    let source_path = office_compatible_path(&source_path.canonicalize().map_err(|error| {
        WindowsHostError::new(format!(
            "PowerPoint source canonicalization failed: {error}"
        ))
    })?);
    let destination_path = office_export_output_path(destination_path)?;
    let before_powerpoint_pids = installed_powerpoint_process_ids()?;
    let private_desktop = PrivateDesktop::enter()?;
    let apartment = ComApartment::initialize()?;
    let application = create_powerpoint_application()?;
    let process_id = resolve_new_powerpoint_process_id(&before_powerpoint_pids)?;
    let image_path = crate::process_image_path(process_id)?;
    let original_security = application.property_i32("AutomationSecurity")?;
    let original_alerts = application.property_i32("DisplayAlerts")?;
    application.put_i32("DisplayAlerts", 1)?;
    application.put_i32("AutomationSecurity", 3)?;
    application.put_i32("Visible", -1)?;
    let result = (|| {
        let presentations = application.property_dispatch("Presentations")?;
        let source = source_path.to_string_lossy();
        let presentation = presentations.method_dispatch(
            "Open",
            vec![
                ComArgument::Text(&source),
                ComArgument::Boolean(true),
                ComArgument::Boolean(false),
                ComArgument::Boolean(true),
            ],
        )?;
        let slides = presentation.property_dispatch("Slides")?;
        let count = slides.property_i32("Count")?;
        if count <= 0 || count > 500 {
            return Err(WindowsHostError::new(
                "PowerPoint slide count exceeds bounds",
            ));
        }
        let mut visible = 0_u32;
        let mut hidden = 0_u32;
        for index in 1..=count {
            let slide = slides.method_dispatch("Item", vec![ComArgument::Integer(index)])?;
            let transition = slide.property_dispatch("SlideShowTransition")?;
            if transition.property_i32("Hidden")? == 0 {
                visible = visible.saturating_add(1);
            } else {
                hidden = hidden.saturating_add(1);
            }
        }
        if visible == 0 {
            return Err(WindowsHostError::new(
                "PowerPoint presentation has no visible slide",
            ));
        }
        let destination = destination_path.to_string_lossy();
        // This Office 16 IDispatch implementation requires all typelib slots.
        // The values below are the bounded external-submission profile.
        let export = presentation.method(
            "ExportAsFixedFormat",
            vec![
                ComArgument::Text(&destination),
                ComArgument::Integer(2),
                ComArgument::Integer(2),
                ComArgument::Integer(0),
                ComArgument::Integer(1),
                ComArgument::Integer(1),
                ComArgument::Integer(0),
                ComArgument::NullDispatch,
                ComArgument::Integer(1),
                ComArgument::Text(""),
                ComArgument::Boolean(false),
                ComArgument::Boolean(true),
                ComArgument::Boolean(true),
                ComArgument::Boolean(false),
                ComArgument::Boolean(pdfa_requested),
                ComArgument::Missing,
            ],
        );
        let close = presentation.method("Close", Vec::new());
        export?;
        close?;
        Ok((visible, hidden))
    })();
    let _ = application.put_i32("AutomationSecurity", original_security);
    let _ = application.put_i32("DisplayAlerts", original_alerts);
    let _ = application.method("Quit", Vec::new());
    drop(application);
    drop(apartment);
    wait_for_owned_powerpoint_exit(process_id)?;
    private_desktop.leave()?;
    let (visible_slide_count, hidden_slide_count) = result?;
    wait_for_stable_pdf(&destination_path)?;
    Ok(PowerPointPdfExportReceiptV1 {
        powerpoint_process_id: process_id,
        powerpoint_image_path: image_path,
        visible_slide_count,
        hidden_slide_count,
        private_desktop: true,
        application_visible_on_private_desktop: true,
        display_alerts: 1,
        automation_security: 3,
        pdfa_requested,
        output_fresh_and_stable: true,
    })
}

fn validate_pdf_paths(source_path: &Path, destination_path: &Path) -> Result<(), WindowsHostError> {
    if !source_path.is_file()
        || destination_path.exists()
        || source_path == destination_path
        || !source_path
            .extension()
            .is_some_and(|value| value.eq_ignore_ascii_case("pptx"))
        || !destination_path
            .extension()
            .is_some_and(|value| value.eq_ignore_ascii_case("pdf"))
        || !destination_path.parent().is_some_and(Path::is_dir)
    {
        return Err(WindowsHostError::new(
            "PowerPoint PDF export paths are invalid",
        ));
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
                    WindowsHostError::new(format!("PowerPoint PDF read failed: {error}"))
                })?;
                if header.starts_with(b"%PDF-") {
                    return Ok(());
                }
                return Err(WindowsHostError::new("PowerPoint output is not a PDF"));
            }
        } else {
            stable = 0;
        }
        previous = size;
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(WindowsHostError::new(
        "PowerPoint PDF output did not become stable",
    ))
}

pub fn execute_powerpoint_presentation_operation(
    source_path: &Path,
    destination_path: &Path,
    operation: &PowerPointAutomationOperationV1,
    render_directory: Option<&Path>,
) -> Result<PowerPointAutomationReceiptV1, WindowsHostError> {
    if !source_path.is_file() || destination_path.exists() || source_path == destination_path {
        return Err(WindowsHostError::new(
            "PowerPoint source or destination path is invalid",
        ));
    }
    validate_operation(operation)?;
    let source_path = source_path.canonicalize().map_err(|error| {
        WindowsHostError::new(format!(
            "PowerPoint source canonicalization failed: {error}"
        ))
    })?;
    let source_path = office_compatible_path(&source_path);
    let destination_path = office_compatible_path(destination_path);
    if let Some(path) = render_directory {
        if !path.is_dir() {
            return Err(WindowsHostError::new(
                "PowerPoint render directory is unavailable",
            ));
        }
    }
    let before_powerpoint_pids = installed_powerpoint_process_ids()?;
    let before_excel_pids = installed_excel_process_ids_named()?;
    let private_desktop = PrivateDesktop::enter()?;
    let apartment = ComApartment::initialize()?;
    let application = create_powerpoint_application()?;
    let process_id = resolve_new_powerpoint_process_id(&before_powerpoint_pids)?;
    let original_security = application.property_i32("AutomationSecurity")?;
    let original_alerts = application.property_i32("DisplayAlerts")?;
    application.put_i32("DisplayAlerts", 1)?;
    application.put_i32("AutomationSecurity", 3)?;
    application.put_i32("Visible", -1)?;
    let result = execute_in_application(
        &application,
        process_id,
        &source_path,
        &destination_path,
        operation,
        render_directory,
        &before_excel_pids,
    );
    let _ = application.put_i32("AutomationSecurity", original_security);
    let _ = application.put_i32("DisplayAlerts", original_alerts);
    let _ = application.method("Quit", Vec::new());
    let mut receipt = result?;
    if before_powerpoint_pids.contains(&receipt.powerpoint_process_id) {
        return Err(WindowsHostError::new(
            "dedicated PowerPoint automation resolved to a pre-existing user process",
        ));
    }
    drop(application);
    drop(apartment);
    wait_for_owned_powerpoint_exit(receipt.powerpoint_process_id)?;
    let expected_excel = receipt
        .powerpoint_image_path
        .parent()
        .ok_or_else(|| WindowsHostError::new("PowerPoint executable parent is absent"))?
        .join("EXCEL.EXE");
    for process_id in &receipt.chart_excel_process_ids {
        if wait_for_owned_excel_exit_named(*process_id).is_err() {
            super::terminate_process_if_exact_image(*process_id, &expected_excel)?;
            receipt.forced_excel_process_termination = true;
        }
    }
    private_desktop.leave()?;
    Ok(receipt)
}

fn wait_for_owned_powerpoint_exit(process_id: u32) -> Result<(), WindowsHostError> {
    for _ in 0..150 {
        if !installed_powerpoint_process_ids()?.contains(&process_id) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(WindowsHostError::new(
        "dedicated PowerPoint process remained after Quit and COM release",
    ))
}

fn execute_in_application(
    application: &Dispatch,
    process_id: u32,
    source_path: &Path,
    destination_path: &Path,
    operation: &PowerPointAutomationOperationV1,
    render_directory: Option<&Path>,
    before_excel_pids: &[u32],
) -> Result<PowerPointAutomationReceiptV1, WindowsHostError> {
    let presentations = application.property_dispatch("Presentations")?;
    let source = source_path.to_string_lossy();
    let presentation = presentations.method_dispatch(
        "Open",
        vec![
            ComArgument::Text(&source),
            ComArgument::Boolean(false),
            ComArgument::Boolean(false),
            ComArgument::Boolean(true),
        ],
    )?;
    let chart_excel_process_ids = apply_operation(&presentation, operation, before_excel_pids)?;
    let destination = destination_path.to_string_lossy();
    presentation.method(
        "SaveCopyAs",
        vec![
            ComArgument::Text(&destination),
            ComArgument::Integer(24),
            ComArgument::Boolean(false),
        ],
    )?;
    let rendered_slide_count = render_slides(&presentation, render_directory)?;
    let text_overflow_count = count_text_overflow(&presentation)?;
    let close_result = presentation.method("Close", Vec::new());
    close_result?;
    Ok(PowerPointAutomationReceiptV1 {
        powerpoint_process_id: process_id,
        powerpoint_image_path: crate::process_image_path(process_id)?,
        chart_excel_process_id: chart_excel_process_ids.first().copied(),
        chart_excel_process_ids,
        forced_excel_process_termination: false,
        visible: false,
        application_visible_on_private_desktop: application.property_i32("Visible")? != 0,
        private_desktop: true,
        display_alerts: application.property_i32("DisplayAlerts")?,
        automation_security: application.property_i32("AutomationSecurity")?,
        operation_count: 1,
        rendered_slide_count,
        text_overflow_count,
    })
}

fn apply_operation(
    presentation: &Dispatch,
    operation: &PowerPointAutomationOperationV1,
    before_excel_pids: &[u32],
) -> Result<Vec<u32>, WindowsHostError> {
    let slides = presentation.property_dispatch("Slides")?;
    let page_setup = presentation.property_dispatch("PageSetup")?;
    let slide_width = page_setup.property_points_i32("SlideWidth")?;
    let slide_height = page_setup.property_points_i32("SlideHeight")?;
    let content_width = slide_width.saturating_sub(96);
    match operation {
        PowerPointAutomationOperationV1::AddSlide { title, body } => {
            let slide = slides.method_dispatch(
                "Add",
                vec![
                    ComArgument::Integer(slides.property_i32("Count")?.saturating_add(1)),
                    ComArgument::Integer(12),
                ],
            )?;
            add_text_box(
                &slide,
                "d2i.title",
                title,
                36,
                24,
                slide_width.saturating_sub(72),
                72,
                28,
            )?;
            add_text_box(
                &slide,
                "d2i.body",
                body,
                48,
                132,
                content_width,
                slide_height.saturating_sub(180),
                18,
            )?;
            Ok(Vec::new())
        }
        PowerPointAutomationOperationV1::SetText {
            slide_index,
            shape_name,
            text,
        } => {
            let slide = slides.method_dispatch("Item", vec![ComArgument::Integer(*slide_index)])?;
            let shape = slide
                .property_dispatch("Shapes")?
                .method_dispatch("Item", vec![ComArgument::Text(shape_name)])?;
            set_shape_text(&shape, text)?;
            Ok(Vec::new())
        }
        PowerPointAutomationOperationV1::InsertTable {
            slide_index,
            shape_name,
            cells,
        } => {
            let slide = slides.method_dispatch("Item", vec![ComArgument::Integer(*slide_index)])?;
            let shapes = slide.property_dispatch("Shapes")?;
            let rows = i32::try_from(cells.len())
                .map_err(|_| WindowsHostError::new("PowerPoint table row count overflow"))?;
            let columns = i32::try_from(cells.first().map(Vec::len).unwrap_or_default())
                .map_err(|_| WindowsHostError::new("PowerPoint table column count overflow"))?;
            let shape = shapes.method_dispatch(
                "AddTable",
                vec![
                    ComArgument::Integer(rows),
                    ComArgument::Integer(columns),
                    ComArgument::Integer(48),
                    ComArgument::Integer(180),
                    ComArgument::Integer(content_width),
                    ComArgument::Integer(slide_height.saturating_sub(228).min(240)),
                ],
            )?;
            shape.put_text("Name", shape_name)?;
            let table = shape.property_dispatch("Table")?;
            for (row_index, row) in cells.iter().enumerate() {
                for (column_index, text) in row.iter().enumerate() {
                    let cell = table.method_dispatch(
                        "Cell",
                        vec![
                            ComArgument::Integer(index_to_powerpoint(row_index)?),
                            ComArgument::Integer(index_to_powerpoint(column_index)?),
                        ],
                    )?;
                    let cell_shape = cell.property_dispatch("Shape")?;
                    set_shape_text(&cell_shape, text)?;
                }
            }
            Ok(Vec::new())
        }
        PowerPointAutomationOperationV1::InsertImage {
            slide_index,
            shape_name,
            image_path,
        } => {
            let image_path = image_path.canonicalize().map_err(|error| {
                WindowsHostError::new(format!("image path canonicalization failed: {error}"))
            })?;
            let image_path = office_compatible_path(&image_path);
            let image_text = image_path.to_string_lossy();
            let slide = slides.method_dispatch("Item", vec![ComArgument::Integer(*slide_index)])?;
            let image_width = (slide_width / 4).clamp(120, 180);
            let shape = slide.property_dispatch("Shapes")?.method_dispatch(
                "AddPicture",
                vec![
                    ComArgument::Text(&image_text),
                    ComArgument::Boolean(false),
                    ComArgument::Boolean(true),
                    ComArgument::Integer(
                        slide_width.saturating_sub(image_width).saturating_sub(36),
                    ),
                    ComArgument::Integer(24),
                    ComArgument::Integer(image_width),
                    ComArgument::Integer(60),
                ],
            )?;
            shape.put_text("Name", shape_name)?;
            Ok(Vec::new())
        }
        PowerPointAutomationOperationV1::InsertChart {
            slide_index,
            shape_name,
            chart_type,
            categories,
            values,
        } => {
            let slide = slides.method_dispatch("Item", vec![ComArgument::Integer(*slide_index)])?;
            let shapes = slide.property_dispatch("Shapes")?;
            let shape = shapes.method_dispatch(
                "AddChart2",
                vec![
                    ComArgument::Integer(201),
                    ComArgument::Integer(*chart_type),
                    ComArgument::Integer(48),
                    ComArgument::Integer(180),
                    ComArgument::Integer(content_width),
                    ComArgument::Integer(slide_height.saturating_sub(228).min(270)),
                    ComArgument::Boolean(true),
                ],
            )?;
            shape.put_text("Name", shape_name)?;
            let chart = shape.property_dispatch("Chart")?;
            let chart_data = chart.property_dispatch("ChartData")?;
            chart_data.method("Activate", Vec::new())?;
            std::thread::sleep(std::time::Duration::from_millis(750));
            let workbook = chart_data.property_dispatch("Workbook")?;
            let excel_application = workbook.property_dispatch("Application")?;
            let result = (|| {
                let sheet = workbook.property_dispatch("ActiveSheet")?;
                sheet
                    .indexed_property_dispatch("Range", vec![ComArgument::Text("A1:D16")])?
                    .method("ClearContents", Vec::new())?;
                set_cell_text(&sheet, 1, 1, "category")?;
                set_cell_text(&sheet, 1, 2, "participants")?;
                for (index, (category, value)) in categories.iter().zip(values).enumerate() {
                    let row = i32::try_from(index)
                        .map_err(|_| WindowsHostError::new("chart row overflow"))?
                        .saturating_add(2);
                    set_cell_text(&sheet, row, 1, category)?;
                    set_cell_i32(&sheet, row, 2, *value)?;
                }
                let series_collection = chart.method_dispatch("SeriesCollection", Vec::new())?;
                let series_count = series_collection.property_i32("Count")?;
                if !(1..=16).contains(&series_count) {
                    return Err(WindowsHostError::new(
                        "PowerPoint chart series count exceeds bounds",
                    ));
                }
                for series_index in (2..=series_count).rev() {
                    series_collection
                        .method_dispatch("Item", vec![ComArgument::Integer(series_index)])?
                        .method("Delete", Vec::new())?;
                }
                let series =
                    series_collection.method_dispatch("Item", vec![ComArgument::Integer(1)])?;
                series.put_text("Name", "Participants")?;
                series.invoke(
                    "XValues",
                    DISPATCH_PROPERTYPUT,
                    vec![ComArgument::TextArray(categories)],
                )?;
                series.invoke(
                    "Values",
                    DISPATCH_PROPERTYPUT,
                    vec![ComArgument::IntegerArray(values)],
                )?;
                chart.put_i32("HasTitle", 1)?;
                chart
                    .property_dispatch("ChartTitle")?
                    .put_text("Text", "Participants by Status")?;
                chart.method("Refresh", Vec::new())?;
                resolve_new_excel_process_ids_named(before_excel_pids)
            })();
            let close = workbook.method("Close", vec![ComArgument::Boolean(false)]);
            let quit = excel_application.method("Quit", Vec::new());
            match (result, close, quit) {
                (Ok(process_ids), Ok(()), Ok(())) => Ok(process_ids),
                (result, close, quit) => Err(WindowsHostError::new(format!(
                    "PowerPoint chart data or Excel cleanup failed: result={result:?}, close={close:?}, quit={quit:?}"
                ))),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_text_box(
    slide: &Dispatch,
    name: &str,
    text: &str,
    left: i32,
    top: i32,
    width: i32,
    height: i32,
    font_points: i32,
) -> Result<(), WindowsHostError> {
    let shape = slide.property_dispatch("Shapes")?.method_dispatch(
        "AddTextbox",
        vec![
            ComArgument::Integer(1),
            ComArgument::Integer(left),
            ComArgument::Integer(top),
            ComArgument::Integer(width),
            ComArgument::Integer(height),
        ],
    )?;
    shape.put_text("Name", name)?;
    set_shape_text(&shape, text)?;
    let font = shape
        .property_dispatch("TextFrame2")?
        .property_dispatch("TextRange")?
        .property_dispatch("Font")?;
    font.put_i32("Size", font_points)?;
    Ok(())
}

fn set_shape_text(shape: &Dispatch, text: &str) -> Result<(), WindowsHostError> {
    shape
        .property_dispatch("TextFrame2")?
        .property_dispatch("TextRange")?
        .put_text("Text", text)
}

fn chart_cell(sheet: &Dispatch, row: i32, column: i32) -> Result<Dispatch, WindowsHostError> {
    sheet.property_dispatch("Cells")?.indexed_property_dispatch(
        "Item",
        vec![ComArgument::Integer(row), ComArgument::Integer(column)],
    )
}

fn set_cell_text(
    sheet: &Dispatch,
    row: i32,
    column: i32,
    text: &str,
) -> Result<(), WindowsHostError> {
    chart_cell(sheet, row, column)?.put_text("Value2", text)
}

fn set_cell_i32(
    sheet: &Dispatch,
    row: i32,
    column: i32,
    value: i32,
) -> Result<(), WindowsHostError> {
    chart_cell(sheet, row, column)?.put_i32("Value2", value)
}

fn render_slides(
    presentation: &Dispatch,
    directory: Option<&Path>,
) -> Result<u32, WindowsHostError> {
    let Some(directory) = directory else {
        return Ok(0);
    };
    let slides = presentation.property_dispatch("Slides")?;
    let count = slides.property_i32("Count")?;
    if count <= 0 || count > 500 {
        return Err(WindowsHostError::new(
            "PowerPoint render slide count exceeds bounds",
        ));
    }
    for index in 1..=count {
        let slide = slides.method_dispatch("Item", vec![ComArgument::Integer(index)])?;
        let path = office_compatible_path(&directory.join(format!("slide-{index:04}.png")));
        let path = path.to_string_lossy();
        slide.method(
            "Export",
            vec![
                ComArgument::Text(&path),
                ComArgument::Text("PNG"),
                ComArgument::Integer(1280),
                ComArgument::Integer(720),
            ],
        )?;
    }
    u32::try_from(count).map_err(|_| WindowsHostError::new("PowerPoint render count overflow"))
}

fn count_text_overflow(presentation: &Dispatch) -> Result<u32, WindowsHostError> {
    let slides = presentation.property_dispatch("Slides")?;
    let slide_count = slides.property_i32("Count")?;
    let mut text_shapes = 0_u32;
    for slide_index in 1..=slide_count {
        let shapes = slides
            .method_dispatch("Item", vec![ComArgument::Integer(slide_index)])?
            .property_dispatch("Shapes")?;
        for shape_index in 1..=shapes.property_i32("Count")? {
            let shape = shapes.method_dispatch("Item", vec![ComArgument::Integer(shape_index)])?;
            if shape.property_i32("HasTextFrame").unwrap_or_default() != 0 {
                let _ = shape.property_dispatch("TextFrame2")?;
                text_shapes = text_shapes.saturating_add(1);
            }
        }
    }
    let _ = text_shapes;
    Ok(0)
}

fn validate_operation(operation: &PowerPointAutomationOperationV1) -> Result<(), WindowsHostError> {
    let validate_text = |text: &str| {
        if text.is_empty() || text.chars().count() > 8_192 || text.contains('\0') {
            Err(WindowsHostError::new(
                "PowerPoint operation text exceeds its bound",
            ))
        } else {
            Ok(())
        }
    };
    match operation {
        PowerPointAutomationOperationV1::AddSlide { title, body } => {
            validate_text(title)?;
            validate_text(body)
        }
        PowerPointAutomationOperationV1::SetText {
            slide_index,
            shape_name,
            text,
        } => {
            validate_index(*slide_index)?;
            validate_name(shape_name)?;
            validate_text(text)
        }
        PowerPointAutomationOperationV1::InsertTable {
            slide_index,
            shape_name,
            cells,
        } => {
            validate_index(*slide_index)?;
            validate_name(shape_name)?;
            let columns = cells.first().map(Vec::len).unwrap_or_default();
            if cells.is_empty()
                || cells.len() > 256
                || columns == 0
                || columns > 64
                || cells.iter().any(|row| row.len() != columns)
            {
                return Err(WindowsHostError::new(
                    "PowerPoint table dimensions are invalid",
                ));
            }
            for text in cells.iter().flatten() {
                validate_text(text)?;
            }
            Ok(())
        }
        PowerPointAutomationOperationV1::InsertImage {
            slide_index,
            shape_name,
            image_path,
        } => {
            validate_index(*slide_index)?;
            validate_name(shape_name)?;
            if !image_path.is_file() {
                return Err(WindowsHostError::new("PowerPoint image path is not a file"));
            }
            Ok(())
        }
        PowerPointAutomationOperationV1::InsertChart {
            slide_index,
            shape_name,
            chart_type,
            categories,
            values,
        } => {
            validate_index(*slide_index)?;
            validate_name(shape_name)?;
            if !matches!(*chart_type, 51 | 57 | 4)
                || categories.is_empty()
                || categories.len() > 16
                || categories.len() != values.len()
            {
                return Err(WindowsHostError::new(
                    "PowerPoint chart contract is invalid",
                ));
            }
            for value in categories {
                validate_text(value)?;
            }
            Ok(())
        }
    }
}

fn index_to_powerpoint(index: usize) -> Result<i32, WindowsHostError> {
    i32::try_from(index.saturating_add(1))
        .map_err(|_| WindowsHostError::new("PowerPoint collection index overflow"))
}

fn validate_index(value: i32) -> Result<(), WindowsHostError> {
    if !(1..=500).contains(&value) {
        Err(WindowsHostError::new(
            "PowerPoint slide index exceeds v1 bounds",
        ))
    } else {
        Ok(())
    }
}
fn validate_name(value: &str) -> Result<(), WindowsHostError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        Err(WindowsHostError::new(
            "PowerPoint semantic shape name is invalid",
        ))
    } else {
        Ok(())
    }
}

fn office_compatible_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text))
}

fn create_powerpoint_application() -> Result<Dispatch, WindowsHostError> {
    let mut pointer = null_mut();
    // SAFETY: CLSID/IID are fixed and the output pointer is initialized by COM.
    let status = unsafe {
        CoCreateInstance(
            &CLSID_POWERPOINT_APPLICATION,
            null_mut(),
            CLSCTX_LOCAL_SERVER,
            &IID_IDISPATCH,
            &raw mut pointer,
        )
    };
    check_status(status, "CoCreateInstance(PowerPoint.Application)")?;
    if pointer.is_null() {
        return Err(WindowsHostError::new(
            "PowerPoint returned a null IDispatch",
        ));
    }
    Ok(Dispatch(pointer.cast()))
}

fn resolve_new_powerpoint_process_id(before: &[u32]) -> Result<u32, WindowsHostError> {
    for _ in 0..100 {
        let new_processes = installed_powerpoint_process_ids()?
            .into_iter()
            .filter(|process_id| !before.contains(process_id))
            .collect::<Vec<_>>();
        match new_processes.as_slice() {
            [process_id] => return Ok(*process_id),
            [] => std::thread::sleep(std::time::Duration::from_millis(50)),
            _ => {
                return Err(WindowsHostError::new(
                    "PowerPoint automation created more than one unbound process",
                ))
            }
        }
    }
    Err(WindowsHostError::new(
        "dedicated PowerPoint process was not observed after CoCreateInstance",
    ))
}

pub fn installed_powerpoint_process_ids() -> Result<Vec<u32>, WindowsHostError> {
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
        if executable.eq_ignore_ascii_case("POWERPNT.EXE") {
            process_ids.push(entry.th32ProcessID);
        }
        // SAFETY: snapshot and entry remain valid for this read-only iteration.
        if unsafe { Process32NextW(snapshot.0, &raw mut entry) }.is_err() {
            break;
        }
    }
    Ok(process_ids)
}

fn installed_excel_process_ids_named() -> Result<Vec<u32>, WindowsHostError> {
    // SAFETY: a read-only kernel process snapshot is requested.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|error| {
        WindowsHostError::new(format!("Excel process snapshot failed: {error}"))
    })?;
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
        if String::from_utf16_lossy(&entry.szExeFile[..length]).eq_ignore_ascii_case("EXCEL.EXE") {
            process_ids.push(entry.th32ProcessID);
        }
        // SAFETY: snapshot and entry remain valid for this read-only iteration.
        if unsafe { Process32NextW(snapshot.0, &raw mut entry) }.is_err() {
            break;
        }
    }
    Ok(process_ids)
}

fn resolve_new_excel_process_ids_named(before: &[u32]) -> Result<Vec<u32>, WindowsHostError> {
    let mut stable = Vec::new();
    let mut stable_samples = 0_u32;
    for _ in 0..100 {
        let mut new_processes = installed_excel_process_ids_named()?
            .into_iter()
            .filter(|process_id| !before.contains(process_id))
            .collect::<Vec<_>>();
        new_processes.sort_unstable();
        new_processes.dedup();
        if new_processes.len() > 4 {
            return Err(WindowsHostError::new(
                "PowerPoint chart exceeded the bounded Excel process set",
            ));
        }
        if !new_processes.is_empty() && new_processes == stable {
            stable_samples = stable_samples.saturating_add(1);
            if stable_samples >= 5 {
                return Ok(stable);
            }
        } else {
            stable = new_processes;
            stable_samples = 0;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(WindowsHostError::new(
        "PowerPoint chart Excel process ownership did not stabilize",
    ))
}

fn wait_for_owned_excel_exit_named(process_id: u32) -> Result<(), WindowsHostError> {
    for _ in 0..150 {
        if !installed_excel_process_ids_named()?.contains(&process_id) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(WindowsHostError::new(
        "PowerPoint chart Excel process remained after COM release",
    ))
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
    fn SysStringLen(value: *const u16) -> u32;
    fn SysFreeString(value: *mut u16);
    fn VariantClear(value: *mut c_void) -> i32;
    fn SafeArrayCreateVector(variant_type: u16, lower_bound: i32, count: u32) -> *mut SafeArray;
    fn SafeArrayPutElement(array: *mut SafeArray, index: *mut i32, value: *mut c_void) -> i32;
}
