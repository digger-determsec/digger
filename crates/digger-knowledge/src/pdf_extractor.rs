/// PDF text extraction — generic layer for converting PDFs to text.
///
/// Provides a common interface for all PDF-based knowledge sources.
/// Each source-specific adapter feeds extracted text into its own parser.
use digger_knowledge_models::*;
use regex::Regex;

/// Extract text from a PDF file path.
pub fn extract_text_from_pdf(path: &str) -> Result<String, ExtractionError> {
    let data = std::fs::read(path).map_err(|e| ExtractionError {
        message: format!("Failed to read PDF: {}", e),
        source_identifier: path.into(),
        line: None,
    })?;

    extract_text_from_bytes(&data, path)
}

/// Extract text from PDF bytes.
pub fn extract_text_from_bytes(data: &[u8], identifier: &str) -> Result<String, ExtractionError> {
    pdf_extract::extract_text_from_mem(data).map_err(|e| ExtractionError {
        message: format!("Failed to extract PDF text: {}", e),
        source_identifier: identifier.into(),
        line: None,
    })
}

/// Clean extracted PDF text — remove excessive whitespace and artifacts.
pub fn clean_pdf_text(text: &str) -> String {
    let mut result = String::new();
    let mut prev_empty = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !prev_empty {
                result.push('\n');
                prev_empty = true;
            }
        } else {
            result.push_str(trimmed);
            result.push('\n');
            prev_empty = false;
        }
    }

    result.trim().to_string()
}

/// Extract metadata from a PDF filename.
/// Common patterns: YYYY-MM-name.pdf, YYYY-MM-DD-name.pdf
pub fn extract_metadata_from_filename(filename: &str) -> PdfMetadata {
    let date_re = match Regex::new(r"(\d{4}-\d{2}(?:-\d{2})?)") {
        Ok(re) => re,
        Err(_) => {
            return PdfMetadata {
                date: None,
                name: filename
                    .replace(".pdf", "")
                    .replace(".PDF", "")
                    .replace(['-', '_'], " ")
                    .trim()
                    .to_string(),
                filename: filename.to_string(),
            };
        }
    };
    let date = date_re.find(filename).map(|m| m.as_str().to_string());

    // Remove date and extension to get the name
    let name = date_re.replace(filename, "");
    let name = name
        .trim_start_matches('-')
        .trim_end_matches(".pdf")
        .trim_end_matches(".PDF")
        .replace(['-', '_'], " ");

    PdfMetadata {
        date,
        name: name.trim().to_string(),
        filename: filename.to_string(),
    }
}

/// Metadata extracted from a PDF filename.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct PdfMetadata {
    pub date: Option<String>,
    pub name: String,
    pub filename: String,
}
