//! `OffsetPage` and `OffsetPageMeta` — **offset** pagination, which is not
//! how the rest of this crate paginates.
//!
//! Two incompatible pagination styles live in the Tamga API and this crate now
//! touches both. Getting them the wrong way round produces code that looks
//! right and silently drops rows, so they are modelled as two different types
//! rather than one type with a mode flag.
//!
//! | Style | Request | Response | Used by |
//! |---|---|---|---|
//! | Keyset (synthetic cursor) | `limit`, `page[after]` | bare `{data: […]}`, no metadata | [`crate::Client::list_components`], [`crate::Client::list_machine_processes`] |
//! | Offset | `page[number]`, `page[size]` | `{data: […], meta: {page: {number, size, total, totalPages}}}` | [`crate::Client::list_machines`] |
//!
//! The keyset routes are the SDK-facing nested sub-collections; they are
//! hand-written queries that return no page metadata at all, so "is this page
//! short?" is the only end-of-listing signal and the caller synthesizes the
//! cursor from the last row's id. The offset routes are the console-facing
//! top-level collections, which run through the server's shared list-query
//! layer and do report a total.
//!
//! `GET /machines` is the only route this crate calls that is offset
//! paginated. Handing it a `page[after]` cursor is not an error — the
//! parameter is simply ignored, and the first page comes back forever, which
//! is exactly the failure mode `page[after]` already has on the entitlements
//! listing (see [`crate::Client::list_entitlements`]) but arrived at from the
//! opposite direction.

/// One page of an offset-paginated collection, plus the server's page
/// metadata.
///
/// Unlike the keyset listings, this one can tell you how much is left:
/// [`OffsetPageMeta::total`] counts every row matching the request's filters,
/// not just the ones on this page.
#[derive(Debug, Clone)]
pub struct OffsetPage<T> {
    /// The rows on this page.
    pub items: Vec<T>,
    /// `meta.page` from the response.
    pub page: OffsetPageMeta,
}

impl<T> OffsetPage<T> {
    /// The 1-based number to request next, or `None` when this is the last
    /// page.
    ///
    /// Prefer this over `items.len() == size`: a filtered collection can
    /// return a short page that is not the last one only if the server
    /// changes underneath you, but a *full* page that happens to be the last
    /// one is routine, and looping on length alone costs one wasted request
    /// every time.
    pub fn next_page_number(&self) -> Option<i64> {
        (self.page.number < self.page.total_pages).then_some(self.page.number + 1)
    }
}

/// `meta.page` on an offset-paginated response.
///
/// Field names on the wire are `number`, `size`, `total` and — the one
/// camelCase key — `totalPages`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OffsetPageMeta {
    /// 1-based page number, after the server floored it to at least 1.
    pub number: i64,
    /// Page size, after the server clamped it to `1..=100`. A request for
    /// more than 100 rows is silently satisfied with 100, so read the size
    /// back from here rather than assuming the one you asked for.
    pub size: i64,
    /// Total rows matching the request's filters — not the size of the whole
    /// table.
    pub total: i64,
    /// `ceil(total / size)`, and `0` when nothing matched.
    #[serde(rename = "totalPages")]
    pub total_pages: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(number: i64, size: i64, total: i64, total_pages: i64) -> OffsetPageMeta {
        OffsetPageMeta {
            number,
            size,
            total,
            total_pages,
        }
    }

    #[test]
    fn deserializes_the_camel_case_total_pages_key() {
        let parsed: OffsetPageMeta =
            serde_json::from_str(r#"{"number":2,"size":25,"total":142,"totalPages":6}"#).unwrap();
        assert_eq!(parsed.number, 2);
        assert_eq!(parsed.size, 25);
        assert_eq!(parsed.total, 142);
        assert_eq!(parsed.total_pages, 6);
    }

    #[test]
    fn next_page_number_advances_until_the_last_page() {
        let page = OffsetPage {
            items: vec![1, 2, 3],
            page: meta(1, 25, 142, 6),
        };
        assert_eq!(page.next_page_number(), Some(2));

        let last = OffsetPage {
            items: vec![1],
            page: meta(6, 25, 142, 6),
        };
        assert_eq!(last.next_page_number(), None);
    }

    #[test]
    fn an_empty_collection_reports_no_next_page() {
        let page: OffsetPage<i32> = OffsetPage {
            items: Vec::new(),
            page: meta(1, 25, 0, 0),
        };
        assert_eq!(page.next_page_number(), None);
    }

    #[test]
    fn a_full_final_page_still_reports_no_next_page() {
        // The reason this type exists rather than a `len() == limit` rule: a
        // full page is not evidence there is another one.
        let page = OffsetPage {
            items: vec![0; 25],
            page: meta(2, 25, 50, 2),
        };
        assert_eq!(page.next_page_number(), None);
    }
}
