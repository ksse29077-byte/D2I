use super::{is_reparse_point, WindowsHostError};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};
use windows::Data::Pdf::{PdfDocument, PdfPageRenderOptions, PdfPageRotation};
use windows::Graphics::Imaging::{BitmapDecoder, BitmapPixelFormat};
use windows::Storage::Streams::{DataReader, DataWriter, InMemoryRandomAccessStream};
use windows::UI::Color;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPdfPageRenderReceiptV1 {
    pub page_index: u32,
    pub width_millipoints: u32,
    pub height_millipoints: u32,
    pub rotation_degrees: u16,
    pub rendered_width_pixels: u32,
    pub rendered_height_pixels: u32,
    pub rendered_png_path: PathBuf,
    pub rendered_png_sha256: String,
    pub non_white_pixel_millionths: u32,
    pub luminance_buckets: Vec<u32>,
    pub color_buckets: Vec<u32>,
    pub edge_buckets: Vec<u32>,
    pub occupancy_buckets: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPdfRenderReceiptV1 {
    pub renderer_backend_id: String,
    pub page_count: u32,
    pub password_protected: bool,
    pub total_rendered_pixels: u64,
    pub pages: Vec<WindowsPdfPageRenderReceiptV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsImageFingerprintV1 {
    pub width_pixels: u32,
    pub height_pixels: u32,
    pub non_white_pixel_millionths: u32,
    pub luminance_buckets: Vec<u32>,
    pub color_buckets: Vec<u32>,
    pub edge_buckets: Vec<u32>,
    pub occupancy_buckets: Vec<u32>,
}

pub fn fingerprint_png_with_windows_imaging(
    png_path: &Path,
) -> Result<WindowsImageFingerprintV1, WindowsHostError> {
    if !png_path.is_file() {
        return Err(WindowsHostError::new("PNG fingerprint input is not a file"));
    }
    let png_path = validated_absolute_regular_file(png_path, "PNG")?;
    let png = fs::read(&png_path)
        .map_err(|error| WindowsHostError::new(format!("PNG read failed: {error}")))?;
    let stream = stream_from_bytes(&png, "PNG", 128 * 1024 * 1024)?;
    let decoder = BitmapDecoder::CreateAsync(&stream)
        .and_then(|operation| operation.join())
        .map_err(winrt("decode PNG fingerprint input"))?;
    let width = decoder.PixelWidth().map_err(winrt("read PNG width"))?;
    let height = decoder.PixelHeight().map_err(winrt("read PNG height"))?;
    let format = decoder
        .BitmapPixelFormat()
        .map_err(winrt("read PNG pixel format"))?;
    if format != BitmapPixelFormat::Bgra8 && format != BitmapPixelFormat::Rgba8 {
        return Err(WindowsHostError::new("PNG pixel format is unsupported"));
    }
    let pixels = decoder
        .GetPixelDataAsync()
        .and_then(|operation| operation.join())
        .and_then(|provider| provider.DetachPixelData())
        .map_err(winrt("read PNG pixels"))?;
    let value = fingerprint(&pixels, width, height, format)?;
    Ok(WindowsImageFingerprintV1 {
        width_pixels: width,
        height_pixels: height,
        non_white_pixel_millionths: value.0,
        luminance_buckets: value.1,
        color_buckets: value.2,
        edge_buckets: value.3,
        occupancy_buckets: value.4,
    })
}

pub fn render_pdf_with_windows_data_pdf(
    pdf_path: &Path,
    output_directory: &Path,
    maximum_pages: u32,
    maximum_total_pixels: u64,
    destination_width_pixels: u32,
) -> Result<WindowsPdfRenderReceiptV1, WindowsHostError> {
    if !pdf_path.is_file()
        || !output_directory.is_dir()
        || maximum_pages == 0
        || maximum_pages > 500
        || maximum_total_pixels == 0
        || maximum_total_pixels > 500_000_000
        || !(1_600..=2_400).contains(&destination_width_pixels)
    {
        return Err(WindowsHostError::new(
            "Windows PDF render inputs exceed bounds",
        ));
    }
    let pdf_path = validated_absolute_regular_file(pdf_path, "PDF")?;
    let pdf = fs::read(&pdf_path)
        .map_err(|error| WindowsHostError::new(format!("PDF read failed: {error}")))?;
    let stream = stream_from_bytes(&pdf, "PDF", 512 * 1024 * 1024)?;
    let document = PdfDocument::LoadFromStreamAsync(&stream)
        .and_then(|operation| operation.join())
        .map_err(|error| WindowsHostError::new(format!("PdfDocument load failed: {error}")))?;
    let password_protected = document.IsPasswordProtected().map_err(|error| {
        WindowsHostError::new(format!("PDF password status query failed: {error}"))
    })?;
    validate_pdf_password_status(password_protected)?;
    let page_count = document
        .PageCount()
        .map_err(|error| WindowsHostError::new(format!("PDF page count failed: {error}")))?;
    if page_count == 0 || page_count > maximum_pages {
        return Err(WindowsHostError::new(
            "PDF page count exceeds its bounded profile",
        ));
    }
    let mut pages = Vec::with_capacity(
        usize::try_from(page_count)
            .map_err(|_| WindowsHostError::new("PDF page count conversion failed"))?,
    );
    let mut total_rendered_pixels = 0_u64;
    for page_index in 0..page_count {
        let page = document.GetPage(page_index).map_err(|error| {
            WindowsHostError::new(format!("PDF page {page_index} open failed: {error}"))
        })?;
        let size = page.Size().map_err(|error| {
            WindowsHostError::new(format!("PDF page {page_index} size failed: {error}"))
        })?;
        if !size.Width.is_finite()
            || !size.Height.is_finite()
            || size.Width <= 0.0
            || size.Height <= 0.0
        {
            return Err(WindowsHostError::new("PDF page geometry is invalid"));
        }
        let width = destination_width_pixels;
        let height = ((f64::from(width) * f64::from(size.Height) / f64::from(size.Width)).round()
            as u64)
            .clamp(1, 10_000);
        let height = u32::try_from(height)
            .map_err(|_| WindowsHostError::new("PDF destination height overflow"))?;
        let page_pixels = u64::from(width).saturating_mul(u64::from(height));
        total_rendered_pixels = total_rendered_pixels.saturating_add(page_pixels);
        if total_rendered_pixels > maximum_total_pixels {
            return Err(WindowsHostError::new("PDF render pixel budget exceeded"));
        }
        let stream = InMemoryRandomAccessStream::new().map_err(|error| {
            WindowsHostError::new(format!("PDF render stream creation failed: {error}"))
        })?;
        let options = PdfPageRenderOptions::new().map_err(|error| {
            WindowsHostError::new(format!("PDF render options creation failed: {error}"))
        })?;
        options
            .SetDestinationWidth(width)
            .map_err(winrt("set PDF render width"))?;
        options
            .SetDestinationHeight(height)
            .map_err(winrt("set PDF render height"))?;
        options
            .SetBackgroundColor(Color {
                A: 255,
                R: 255,
                G: 255,
                B: 255,
            })
            .map_err(winrt("set PDF white background"))?;
        options
            .SetIsIgnoringHighContrast(true)
            .map_err(winrt("disable PDF high contrast"))?;
        options
            .SetBitmapEncoderId(
                windows::Graphics::Imaging::BitmapEncoder::PngEncoderId()
                    .map_err(winrt("resolve PNG encoder"))?,
            )
            .map_err(winrt("set PNG encoder"))?;
        page.RenderWithOptionsToStreamAsync(&stream, &options)
            .and_then(|operation| operation.join())
            .map_err(|error| {
                WindowsHostError::new(format!("PDF page {page_index} render failed: {error}"))
            })?;
        let png = read_stream(&stream)?;
        if png.len() < 8 || png[..8] != [137, 80, 78, 71, 13, 10, 26, 10] {
            return Err(WindowsHostError::new("PDF renderer did not produce PNG"));
        }
        let png_path = output_directory.join(format!("page-{page_index:04}.png"));
        if png_path.exists() {
            return Err(WindowsHostError::new("PDF render output already exists"));
        }
        fs::write(&png_path, &png).map_err(|error| {
            WindowsHostError::new(format!("PDF PNG evidence write failed: {error}"))
        })?;
        // DataReader consumes the render stream, so independently decode the
        // persisted PNG rather than depending on a reusable stream cursor.
        let fingerprint = fingerprint_png_with_windows_imaging(&png_path)?;
        if fingerprint.width_pixels != width || fingerprint.height_pixels != height {
            return Err(WindowsHostError::new("decoded PNG geometry differs"));
        }
        let rotation = rotation_degrees(page.Rotation().map_err(winrt("read PDF rotation"))?);
        page.Close().map_err(winrt("close PDF page"))?;
        pages.push(WindowsPdfPageRenderReceiptV1 {
            page_index,
            width_millipoints: dips_to_millipoints(size.Width)?,
            height_millipoints: dips_to_millipoints(size.Height)?,
            rotation_degrees: rotation,
            rendered_width_pixels: width,
            rendered_height_pixels: height,
            rendered_png_path: png_path,
            rendered_png_sha256: format!("sha256:{:x}", Sha256::digest(&png)),
            non_white_pixel_millionths: fingerprint.non_white_pixel_millionths,
            luminance_buckets: fingerprint.luminance_buckets,
            color_buckets: fingerprint.color_buckets,
            edge_buckets: fingerprint.edge_buckets,
            occupancy_buckets: fingerprint.occupancy_buckets,
        });
    }
    Ok(WindowsPdfRenderReceiptV1 {
        renderer_backend_id: "windows_pdf_render".to_owned(),
        page_count,
        password_protected,
        total_rendered_pixels,
        pages,
    })
}

pub fn validate_pdf_password_status(password_protected: bool) -> Result<(), WindowsHostError> {
    if password_protected {
        return Err(WindowsHostError::new(
            "password-protected PDF is unsupported",
        ));
    }
    Ok(())
}

fn read_stream(stream: &InMemoryRandomAccessStream) -> Result<Vec<u8>, WindowsHostError> {
    let size = stream
        .Size()
        .map_err(winrt("read PDF render stream size"))?;
    if size == 0 || size > 128 * 1024 * 1024 {
        return Err(WindowsHostError::new("rendered PNG exceeds its byte bound"));
    }
    stream.Seek(0).map_err(winrt("seek PDF render stream"))?;
    let reader = DataReader::CreateDataReader(stream).map_err(winrt("create PNG reader"))?;
    let size = u32::try_from(size)
        .map_err(|_| WindowsHostError::new("rendered PNG size conversion failed"))?;
    let loaded = reader
        .LoadAsync(size)
        .and_then(|operation| operation.join())
        .map_err(winrt("load PNG stream"))?;
    if loaded != size {
        return Err(WindowsHostError::new("rendered PNG stream was truncated"));
    }
    let mut bytes = vec![
        0_u8;
        usize::try_from(size).map_err(|_| {
            WindowsHostError::new("rendered PNG allocation conversion failed")
        })?
    ];
    reader
        .ReadBytes(&mut bytes)
        .map_err(winrt("read PNG bytes"))?;
    Ok(bytes)
}

fn stream_from_bytes(
    bytes: &[u8],
    label: &str,
    maximum_bytes: usize,
) -> Result<InMemoryRandomAccessStream, WindowsHostError> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(WindowsHostError::new(format!(
            "{label} input exceeds its byte bound"
        )));
    }
    let stream = InMemoryRandomAccessStream::new().map_err(|error| {
        WindowsHostError::new(format!("{label} stream creation failed: {error}"))
    })?;
    let writer = DataWriter::CreateDataWriter(&stream).map_err(|error| {
        WindowsHostError::new(format!("{label} writer creation failed: {error}"))
    })?;
    writer
        .WriteBytes(bytes)
        .map_err(|error| WindowsHostError::new(format!("{label} stream write failed: {error}")))?;
    let stored = writer
        .StoreAsync()
        .and_then(|operation| operation.join())
        .map_err(|error| WindowsHostError::new(format!("{label} stream store failed: {error}")))?;
    if usize::try_from(stored).ok() != Some(bytes.len()) {
        return Err(WindowsHostError::new(format!(
            "{label} stream write was truncated"
        )));
    }
    writer
        .DetachStream()
        .map_err(|error| WindowsHostError::new(format!("{label} stream detach failed: {error}")))?;
    stream
        .Seek(0)
        .map_err(|error| WindowsHostError::new(format!("{label} stream seek failed: {error}")))?;
    Ok(stream)
}

type Fingerprint = (u32, Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>);

fn fingerprint(
    pixels: &[u8],
    width: u32,
    height: u32,
    format: BitmapPixelFormat,
) -> Result<Fingerprint, WindowsHostError> {
    let expected = u64::from(width)
        .saturating_mul(u64::from(height))
        .saturating_mul(4);
    if u64::try_from(pixels.len()).ok() != Some(expected) {
        return Err(WindowsHostError::new("rendered PNG pixel buffer differs"));
    }
    let mut luminance = vec![0_u32; 16];
    let mut color = vec![0_u32; 8];
    let mut edge = vec![0_u32; 16];
    let mut occupancy = vec![0_u32; 64];
    let mut non_white = 0_u64;
    let width_usize = usize::try_from(width)
        .map_err(|_| WindowsHostError::new("render width conversion failed"))?;
    for (index, pixel) in pixels.chunks_exact(4).enumerate() {
        let (red, green, blue) = if format == BitmapPixelFormat::Bgra8 {
            (pixel[2], pixel[1], pixel[0])
        } else {
            (pixel[0], pixel[1], pixel[2])
        };
        let light =
            (u32::from(red) * 2126 + u32::from(green) * 7152 + u32::from(blue) * 722) / 10_000;
        luminance[usize::try_from(light / 16).unwrap_or_default().min(15)] =
            luminance[usize::try_from(light / 16).unwrap_or_default().min(15)].saturating_add(1);
        let color_index =
            usize::from(red >= 128) * 4 + usize::from(green >= 128) * 2 + usize::from(blue >= 128);
        color[color_index] = color[color_index].saturating_add(1);
        if red < 250 || green < 250 || blue < 250 {
            non_white = non_white.saturating_add(1);
            let x = index % width_usize;
            let y = index / width_usize;
            let cell_x = (x.saturating_mul(8) / width_usize).min(7);
            let height_usize = usize::try_from(height)
                .map_err(|_| WindowsHostError::new("render height conversion failed"))?;
            let cell_y = (y.saturating_mul(8) / height_usize).min(7);
            occupancy[cell_y * 8 + cell_x] = occupancy[cell_y * 8 + cell_x].saturating_add(1);
        }
        if index > 0 {
            let previous = &pixels[index.saturating_sub(1) * 4..index * 4];
            let delta = red
                .abs_diff(
                    previous[if format == BitmapPixelFormat::Bgra8 {
                        2
                    } else {
                        0
                    }],
                )
                .max(green.abs_diff(previous[1]))
                .max(blue.abs_diff(
                    previous[if format == BitmapPixelFormat::Bgra8 {
                        0
                    } else {
                        2
                    }],
                ));
            let bucket = usize::from(delta / 16).min(15);
            edge[bucket] = edge[bucket].saturating_add(1);
        }
    }
    let total = u64::from(width).saturating_mul(u64::from(height));
    let non_white = u32::try_from(non_white.saturating_mul(1_000_000) / total)
        .map_err(|_| WindowsHostError::new("pixel occupancy conversion failed"))?;
    Ok((non_white, luminance, color, edge, occupancy))
}

fn dips_to_millipoints(value: f32) -> Result<u32, WindowsHostError> {
    // Windows.Data.Pdf reports page geometry in 96-DPI device-independent
    // pixels. One DIP is 0.75 point, or 750 millipoints.
    let value = f64::from(value) * 750.0;
    if !value.is_finite() || value <= 0.0 || value > f64::from(u32::MAX) {
        return Err(WindowsHostError::new(
            "PDF page DIP geometry exceeds bounds",
        ));
    }
    Ok(value.round() as u32)
}

fn rotation_degrees(rotation: PdfPageRotation) -> u16 {
    match rotation {
        PdfPageRotation::Rotate90 => 90,
        PdfPageRotation::Rotate180 => 180,
        PdfPageRotation::Rotate270 => 270,
        _ => 0,
    }
}

fn winrt(operation: &'static str) -> impl FnOnce(windows::core::Error) -> WindowsHostError {
    move |error| WindowsHostError::new(format!("{operation} failed: {error}"))
}

fn validated_absolute_regular_file(path: &Path, label: &str) -> Result<PathBuf, WindowsHostError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || !path.is_file()
        || fs::symlink_metadata(path)
            .map_err(|error| {
                WindowsHostError::new(format!("{label} metadata inspection failed: {error}"))
            })?
            .file_type()
            .is_symlink()
        || is_reparse_point(path)?
    {
        return Err(WindowsHostError::new(format!(
            "{label} path is not an absolute regular non-reparse file"
        )));
    }
    // AppContainer can read the exact ACL-bound file while Win32 final-path
    // canonicalization remains broker-denied. The caller supplies a copied,
    // absolute, parent-free path and the checks above reject path indirection.
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod geometry_tests {
    use super::{
        dips_to_millipoints, render_pdf_with_windows_data_pdf, validate_pdf_password_status,
    };
    use std::fs;

    #[test]
    fn converts_windows_pdf_dips_to_millipoints() {
        assert_eq!(dips_to_millipoints(960.0).ok(), Some(720_000));
        assert_eq!(dips_to_millipoints(720.0).ok(), Some(540_000));
        assert!(dips_to_millipoints(0.0).is_err());
    }

    #[test]
    fn malformed_pdf_loader_and_password_status_fail_closed() {
        let unique = format!(
            "d2i-office500-malformed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or_default()
        );
        let root = std::env::temp_dir().join(unique);
        let output = root.join("render");
        fs::create_dir_all(&output).unwrap_or_else(|error| panic!("fixture directory: {error}"));
        let malformed = root.join("malformed.pdf");
        fs::write(&malformed, b"%PDF-1.7\nnot-a-valid-pdf\n%%EOF")
            .unwrap_or_else(|error| panic!("fixture write: {error}"));
        let result = render_pdf_with_windows_data_pdf(&malformed, &output, 1, 10_000_000, 1_600);
        assert!(result.is_err());
        assert!(fs::read_dir(&output)
            .map(|entries| entries.count() == 0)
            .unwrap_or(false));
        assert!(validate_pdf_password_status(true).is_err());
        assert!(validate_pdf_password_status(false).is_ok());
        fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("fixture cleanup: {error}"));
    }
}
