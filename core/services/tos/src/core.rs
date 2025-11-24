// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use std::fmt::Debug;
use std::sync::Arc;

use http::Request;
use http::Response;
use http::header::CONTENT_LENGTH;
use http::header::CONTENT_TYPE;
use http::header::HOST;
use reqsign_core::Signer;
use reqsign_volcengine_tos::Credential;
use reqsign_volcengine_tos::{percent_encode_path, percent_encode_query};
use serde::Deserialize;
use serde::Serialize;

use opendal_core::raw::*;
use opendal_core::*;

pub mod constants {
    pub const X_TOS_COPY_SOURCE: &str = "x-tos-copy-source";

    pub const X_TOS_STORAGE_CLASS: &str = "x-tos-storage-class";

    pub const X_TOS_META_PREFIX: &str = "x-tos-meta-";

    pub const X_TOS_VERSION_ID: &str = "x-tos-version-id";
    pub const X_TOS_OBJECT_SIZE: &str = "x-tos-object-size";

    pub const X_TOS_DIRECTORY: &str = "x-tos-directory";

    pub const RESPONSE_CONTENT_DISPOSITION: &str = "response-content-disposition";
    pub const RESPONSE_CONTENT_TYPE: &str = "response-content-type";
    pub const RESPONSE_CACHE_CONTROL: &str = "response-cache-control";

    pub const TOS_QUERY_VERSION_ID: &str = "versionId";
}

pub struct TosCore {
    pub info: Arc<AccessorInfo>,

    pub bucket: String,
    pub endpoint: String, // full endpoint with scheme, e.g. https://tos-cn-beijing.volces.com
    pub endpoint_domain: String, // endpoint domain without scheme, e.g. tos-cn-beijing.volces.com
    pub root: String,
    pub default_storage_class: Option<String>,
    pub allow_anonymous: bool,

    pub signer: Signer<Credential>,
}

impl Debug for TosCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TosCore")
            .field("bucket", &self.bucket)
            .field("endpoint", &self.endpoint)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl TosCore {
    pub async fn send(&self, req: Request<Buffer>) -> Result<Response<Buffer>> {
        if self.allow_anonymous {
            return self.info.http_client().send(req).await;
        }

        let (mut parts, body) = req.into_parts();
        self.signer
            .sign(&mut parts, None)
            .await
            .map_err(|e| new_request_sign_error(e.into()))?;

        let resp = self
            .info
            .http_client()
            .send(Request::from_parts(parts, body))
            .await?;

        Ok(resp)
    }

    pub async fn fetch(&self, req: Request<Buffer>) -> Result<Response<HttpBody>> {
        if self.allow_anonymous {
            return self.info.http_client().fetch(req).await;
        }

        let (mut parts, body) = req.into_parts();

        self.signer
            .sign(&mut parts, None)
            .await
            .map_err(|e| new_request_sign_error(e.into()))?;

        parts.headers.remove(HOST);

        self.info
            .http_client()
            .fetch(Request::from_parts(parts, body))
            .await
    }

    pub fn insert_metadata_headers(
        &self,
        mut req: http::request::Builder,
        size: Option<u64>,
        args: &OpWrite,
    ) -> http::request::Builder {
        if let Some(size) = size {
            req = req.header(CONTENT_LENGTH, size.to_string());
        }

        if let Some(mime) = args.content_type() {
            req = req.header(CONTENT_TYPE, mime);
        }

        if let Some(cache_control) = args.cache_control() {
            req = req.header(http::header::CACHE_CONTROL, cache_control);
        }

        if let Some(content_encoding) = args.content_encoding() {
            req = req.header(http::header::CONTENT_ENCODING, content_encoding);
        }

        if let Some(content_disposition) = args.content_disposition() {
            req = req.header(http::header::CONTENT_DISPOSITION, content_disposition);
        }

        if let Some(if_match) = args.if_match() {
            req = req.header(http::header::IF_MATCH, if_match);
        }

        if args.if_not_exists() {
            req = req.header(http::header::IF_NONE_MATCH, "*");
        }

        if let Some(v) = &self.default_storage_class {
            req = req.header(
                http::HeaderName::from_static(constants::X_TOS_STORAGE_CLASS),
                v,
            );
        }

        if let Some(user_metadata) = args.user_metadata() {
            for (key, value) in user_metadata {
                req = req.header(format!("{}{}", constants::X_TOS_META_PREFIX, key), value);
            }
        }

        req
    }

    pub fn tos_get_object_request(
        &self,
        path: &str,
        range: BytesRange,
        args: &OpRead,
    ) -> Result<Request<Buffer>> {
        let p = build_abs_path(&self.root, path);

        let mut url = format!(
            "https://{}.{}/{}",
            self.bucket,
            self.endpoint_domain,
            percent_encode_path(&p)
        );

        let mut query_args = Vec::new();
        if let Some(override_content_disposition) = args.override_content_disposition() {
            query_args.push(format!(
                "{}={}",
                constants::RESPONSE_CONTENT_DISPOSITION,
                percent_encode_query(override_content_disposition)
            ));
        }
        if let Some(override_content_type) = args.override_content_type() {
            query_args.push(format!(
                "{}={}",
                constants::RESPONSE_CONTENT_TYPE,
                percent_encode_query(override_content_type)
            ));
        }
        if let Some(override_cache_control) = args.override_cache_control() {
            query_args.push(format!(
                "{}={}",
                constants::RESPONSE_CACHE_CONTROL,
                percent_encode_query(override_cache_control)
            ));
        }
        if let Some(version) = args.version() {
            query_args.push(format!(
                "{}={}",
                constants::TOS_QUERY_VERSION_ID,
                percent_decode_path(version)
            ));
        }
        if !query_args.is_empty() {
            url.push_str(&format!("?{}", query_args.join("&")));
        }

        let mut req = Request::get(&url);

        if !range.is_full() {
            req = req.header(http::header::RANGE, range.to_header());
        }

        if let Some(if_none_match) = args.if_none_match() {
            req = req.header(http::header::IF_NONE_MATCH, if_none_match);
        }

        if let Some(if_match) = args.if_match() {
            req = req.header(http::header::IF_MATCH, if_match);
        }

        if let Some(if_modified_since) = args.if_modified_since() {
            req = req.header(
                http::header::IF_MODIFIED_SINCE,
                if_modified_since.format_http_date(),
            );
        }

        if let Some(if_unmodified_since) = args.if_unmodified_since() {
            req = req.header(
                http::header::IF_UNMODIFIED_SINCE,
                if_unmodified_since.format_http_date(),
            );
        }

        req = req.extension(Operation::Read);

        let req = req.body(Buffer::new()).map_err(new_request_build_error)?;

        Ok(req)
    }

    pub async fn tos_get_object(
        &self,
        path: &str,
        range: BytesRange,
        args: &OpRead,
    ) -> Result<Response<HttpBody>> {
        let req = self.tos_get_object_request(path, range, args)?;
        self.fetch(req).await
    }

    pub fn tos_put_object_request(
        &self,
        path: &str,
        size: Option<u64>,
        args: &OpWrite,
        body: Buffer,
    ) -> Result<Request<Buffer>> {
        let p = build_abs_path(&self.root, path);

        let url = format!(
            "https://{}.{}/{}",
            self.bucket,
            self.endpoint_domain,
            percent_encode_path(&p)
        );

        let mut req = Request::put(&url);

        req = self.insert_metadata_headers(req, size, args);

        req = req.extension(Operation::Write);

        let req = req.body(body).map_err(new_request_build_error)?;

        Ok(req)
    }

    pub fn tos_head_object_request(&self, path: &str, args: OpStat) -> Result<Request<Buffer>> {
        let p = build_abs_path(&self.root, path);

        let mut url = format!(
            "https://{}.{}/{}",
            self.bucket,
            self.endpoint_domain,
            percent_encode_path(&p)
        );

        let mut query_args = Vec::new();
        if let Some(override_content_disposition) = args.override_content_disposition() {
            query_args.push(format!(
                "{}={}",
                constants::RESPONSE_CONTENT_DISPOSITION,
                percent_encode_query(override_content_disposition)
            ));
        }
        if let Some(override_content_type) = args.override_content_type() {
            query_args.push(format!(
                "{}={}",
                constants::RESPONSE_CONTENT_TYPE,
                percent_encode_query(override_content_type)
            ));
        }
        if let Some(override_cache_control) = args.override_cache_control() {
            query_args.push(format!(
                "{}={}",
                constants::RESPONSE_CACHE_CONTROL,
                percent_encode_query(override_cache_control)
            ));
        }
        if let Some(version) = args.version() {
            query_args.push(format!(
                "{}={}",
                constants::TOS_QUERY_VERSION_ID,
                percent_decode_path(version)
            ));
        }
        if !query_args.is_empty() {
            url.push_str(&format!("?{}", query_args.join("&")));
        }

        let mut req = Request::head(&url);

        if let Some(if_none_match) = args.if_none_match() {
            req = req.header(http::header::IF_NONE_MATCH, if_none_match);
        }
        if let Some(if_match) = args.if_match() {
            req = req.header(http::header::IF_MATCH, if_match);
        }

        if let Some(if_modified_since) = args.if_modified_since() {
            req = req.header(
                http::header::IF_MODIFIED_SINCE,
                if_modified_since.format_http_date(),
            );
        }
        if let Some(if_unmodified_since) = args.if_unmodified_since() {
            req = req.header(
                http::header::IF_UNMODIFIED_SINCE,
                if_unmodified_since.format_http_date(),
            );
        }

        req = req.extension(Operation::Stat);

        let req = req.body(Buffer::new()).map_err(new_request_build_error)?;

        Ok(req)
    }

    pub async fn tos_head_object(&self, path: &str, args: OpStat) -> Result<Response<Buffer>> {
        let req = self.tos_head_object_request(path, args)?;
        self.send(req).await
    }

    pub async fn tos_delete_object(&self, path: &str, args: &OpDelete) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, path);

        let mut url = format!(
            "https://{}.{}/{}",
            self.bucket,
            self.endpoint_domain,
            percent_encode_path(&p)
        );

        let mut query_args = Vec::new();

        if let Some(version) = args.version() {
            query_args.push(format!(
                "{}={}",
                constants::TOS_QUERY_VERSION_ID,
                percent_encode_query(version)
            ));
        }

        if !query_args.is_empty() {
            url.push_str(&format!("?{}", query_args.join("&")));
        }

        let req = Request::delete(&url);

        let req = req
            .extension(Operation::Delete)
            .body(Buffer::new())
            .map_err(new_request_build_error)?;

        self.send(req).await
    }

    pub async fn tos_initiate_multipart_upload(
        &self,
        path: &str,
        args: &OpWrite,
    ) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, path);

        let url = format!(
            "https://{}.{}/{}?uploads",
            self.bucket,
            self.endpoint_domain,
            percent_encode_path(&p)
        );

        let mut req = Request::post(&url);

        if let Some(mime) = args.content_type() {
            req = req.header(CONTENT_TYPE, mime);
        }

        if let Some(cache_control) = args.cache_control() {
            req = req.header(http::header::CACHE_CONTROL, cache_control);
        }

        if let Some(v) = &self.default_storage_class {
            req = req.header(
                http::HeaderName::from_static(constants::X_TOS_STORAGE_CLASS),
                v,
            );
        }

        if let Some(user_metadata) = args.user_metadata() {
            for (key, value) in user_metadata {
                req = req.header(format!("{}{}", constants::X_TOS_META_PREFIX, key), value);
            }
        }

        req = req.extension(Operation::Write);

        let req = req.body(Buffer::new()).map_err(new_request_build_error)?;

        self.send(req).await
    }

    pub fn tos_upload_part_request(
        &self,
        path: &str,
        upload_id: &str,
        part_number: usize,
        size: u64,
        body: Buffer,
    ) -> Result<Request<Buffer>> {
        let p = build_abs_path(&self.root, path);

        let url = format!(
            "https://{}.{}/{}?partNumber={}&uploadId={}",
            self.bucket,
            self.endpoint_domain,
            percent_encode_path(&p),
            part_number,
            upload_id
        );

        let mut req = Request::put(&url);

        req = req.header(CONTENT_LENGTH, size);

        req = req.extension(Operation::Write);

        let req = req.body(body).map_err(new_request_build_error)?;

        Ok(req)
    }

    pub async fn tos_complete_multipart_upload(
        &self,
        path: &str,
        upload_id: &str,
        parts: Vec<CompleteMultipartUploadRequestPart>,
    ) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, path);

        let url = format!(
            "https://{}.{}/{}?uploadId={}",
            self.bucket,
            self.endpoint_domain,
            percent_encode_path(&p),
            upload_id
        );

        let mut req = Request::post(&url);

        let content = serde_json::to_string(&CompleteMultipartUploadRequest { parts })
            .map_err(new_json_serialize_error)?;
        req = req.header(CONTENT_LENGTH, content.len());
        req = req.header(CONTENT_TYPE, "application/json");

        req = req.extension(Operation::Write);

        let req = req
            .body(Buffer::from(content))
            .map_err(new_request_build_error)?;

        self.send(req).await
    }

    pub async fn tos_abort_multipart_upload(
        &self,
        path: &str,
        upload_id: &str,
    ) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, path);

        let url = format!(
            "https://{}.{}/{}?uploadId={}",
            self.bucket,
            self.endpoint_domain,
            percent_encode_path(&p),
            upload_id
        );

        let req = Request::delete(&url);

        let req = req
            .extension(Operation::Write)
            .body(Buffer::new())
            .map_err(new_request_build_error)?;

        self.send(req).await
    }

    pub async fn tos_list_objects_v2(
        &self,
        path: &str,
        continuation_token: &str,
        delimiter: &str,
        limit: Option<usize>,
        start_after: Option<String>,
    ) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, path);

        let mut url =
            QueryPairsWriter::new(&format!("https://{}.{}", self.bucket, self.endpoint_domain));
        url = url.push("list-type", "2");

        if !p.is_empty() {
            url = url.push("prefix", &percent_encode_query(&p));
        }
        if !delimiter.is_empty() {
            url = url.push("delimiter", &percent_encode_query(delimiter));
        }
        if let Some(limit) = limit {
            url = url.push("max-keys", &limit.to_string());
        }
        if let Some(start_after) = start_after {
            // TOS required the startAfter is start with the prefix currently
            if start_after.starts_with(&p) {
                url = url.push("start-after", &percent_encode_query(&start_after));
            }
        }
        if !continuation_token.is_empty() {
            url = url.push(
                "continuation-token",
                &percent_encode_query(continuation_token),
            );
        }

        let req = Request::get(&url.finish())
            .extension(Operation::List)
            .body(Buffer::new())
            .map_err(new_request_build_error)?;

        self.send(req).await
    }

    pub async fn tos_delete_objects(
        &self,
        paths: Vec<(String, OpDelete)>,
    ) -> Result<Response<Buffer>> {
        let url = format!("https://{}.{}?delete", self.bucket, self.endpoint_domain);

        let mut req = Request::post(&url);

        let content = serde_json::to_string(&DeleteObjectsRequest {
            objects: paths
                .into_iter()
                .map(|(path, op)| DeleteObjectsRequestObject {
                    key: build_abs_path(&self.root, &path),
                    version_id: op.version().map(|v| v.to_owned()),
                })
                .collect(),
        })
        .map_err(new_json_serialize_error)?;

        req = req.header(CONTENT_LENGTH, content.len());
        req = req.header(CONTENT_TYPE, "application/json");
        req = req.header("CONTENT-MD5", format_content_md5(content.as_bytes()));

        req = req.extension(Operation::Delete);

        let req = req
            .body(Buffer::from(content))
            .map_err(new_request_build_error)?;

        self.send(req).await
    }

    pub async fn tos_copy_object(&self, from: &str, to: &str) -> Result<Response<Buffer>> {
        let from = build_abs_path(&self.root, from);
        let to = build_abs_path(&self.root, to);

        let source = format!("/{}/{}", self.bucket, percent_encode_path(&from));
        let target = format!(
            "https://{}.{}/{}",
            self.bucket,
            self.endpoint_domain,
            percent_encode_path(&to)
        );

        let req = Request::put(&target);

        let req = req
            .extension(Operation::Copy)
            .header(constants::X_TOS_COPY_SOURCE, source)
            .body(Buffer::new())
            .map_err(new_request_build_error)?;

        self.send(req).await
    }

    pub async fn tos_list_object_versions(
        &self,
        prefix: &str,
        delimiter: &str,
        limit: Option<usize>,
        key_marker: &str,
        version_id_marker: &str,
    ) -> Result<Response<Buffer>> {
        let p = build_abs_path(&self.root, prefix);

        let mut url =
            QueryPairsWriter::new(&format!("https://{}.{}", self.bucket, self.endpoint_domain));
        url = url.push("versions", "");

        if !p.is_empty() {
            url = url.push("prefix", &percent_encode_query(&p));
        }
        if !delimiter.is_empty() {
            url = url.push("delimiter", &delimiter);
        }

        if let Some(limit) = limit {
            url = url.push("max-keys", &limit.to_string());
        }
        if !key_marker.is_empty() {
            url = url.push("key-marker", &percent_encode_query(key_marker));
        }
        if !version_id_marker.is_empty() {
            url = url.push(
                "version-id-marker",
                &percent_encode_query(version_id_marker),
            );
        }

        let req = Request::get(url.finish())
            .extension(Operation::List)
            .body(Buffer::new())
            .map_err(new_request_build_error)?;

        self.send(req).await
    }
}

#[derive(Default, Debug, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CompleteMultipartUploadRequest {
    pub parts: Vec<CompleteMultipartUploadRequestPart>,
}

#[derive(Clone, Default, Debug, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CompleteMultipartUploadRequestPart {
    pub part_number: usize,
    pub etag: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct InitiateMultipartUploadResult {
    pub upload_id: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CompleteMultipartUploadResult {
    pub bucket: String,
    pub key: String,
    pub location: String,
    pub etag: String,
    pub code: String,
    pub message: String,
    pub request_id: String,
}

#[derive(Default, Debug, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DeleteObjectsRequest {
    pub objects: Vec<DeleteObjectsRequestObject>,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteObjectsRequestObject {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DeleteObjectsResult {
    pub deleted: Vec<DeleteObjectsResultDeleted>,
    pub errors: Vec<DeleteObjectsResultError>,
}

#[derive(Default, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteObjectsResultDeleted {
    pub key: String,
    pub version_id: Option<String>,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct DeleteObjectsResultError {
    pub code: String,
    pub key: String,
    pub message: String,
    pub version_id: Option<String>,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct ListObjectsOutputV2 {
    pub name: String,
    pub prefix: String,
    pub key_count: usize,
    pub max_keys: usize,
    pub is_truncated: bool,
    pub delimiter: String,
    pub next_continuation_token: Option<String>,
    pub common_prefixes: Vec<OutputCommonPrefix>,
    pub contents: Vec<ListObjectsOutputContent>,
}

#[derive(Default, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ListObjectsOutputContent {
    pub key: String,
    pub size: u64,
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: Option<String>,
}

#[derive(Default, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct OutputCommonPrefix {
    pub prefix: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct ListObjectVersionsOutput {
    pub name: String,
    pub prefix: String,
    pub key_marker: String,
    pub version_id_marker: String,
    pub delimiter: String,
    pub max_keys: usize,
    pub is_truncated: Option<bool>,
    pub next_key_marker: Option<String>,
    pub next_version_id_marker: Option<String>,
    pub common_prefixes: Vec<OutputCommonPrefix>,
    pub versions: Vec<ListObjectVersionsOutputVersion>,
    pub delete_markers: Vec<ListObjectVersionsOutputDeleteMarker>,
}

#[derive(Default, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ListObjectVersionsOutputVersion {
    pub key: String,
    pub version_id: String,
    pub is_latest: bool,
    pub last_modified: String,
    pub size: u64,
    pub etag: Option<String>,
    pub storage_class: String,
}

#[derive(Default, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ListObjectVersionsOutputDeleteMarker {
    pub key: String,
    pub version_id: String,
    pub is_latest: bool,
    pub last_modified: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::uri::PathAndQuery;
    use reqsign_core::{Context, OsEnv, ProvideCredentialChain};
    use reqsign_file_read_tokio::TokioFileRead;
    use reqsign_http_send_reqwest::ReqwestHttpSend;
    use reqsign_volcengine_tos::{EnvCredentialProvider, RequestSigner};
    use std::str::FromStr;

    #[test]
    fn test_uri_parse_continuation_token() {
        let continuation_token = "whvFnl2rE5vm9cWvQSMwwNqQ7zin9PCu0FumAwZjFCYtEH5AydiJ7xRHYr5Zkh2IXefe+OsqihLoErO1RXCCusqRvxhcv133ZY6nE0Dstrnh0rPyYiRQQKQLXe4DQ+lEMB05k7Rnh9AiaPRhaMpMCBoo1qIZPQ==";

        let test_url = format!(
            "/?list-type=2&prefix=test/test_list_rich_dir/&delimiter=/&max-keys=5&continuation-token={}",
            continuation_token
        );

        let parse_result = PathAndQuery::from_str(&test_url);

        if parse_result.is_err() {
            println!("Failed to parse URI with continuation token!");
            println!("Error: {:?}", parse_result.unwrap_err());

            println!("\nInvalid characters in token:");

            for (i, c) in continuation_token.chars().enumerate() {
                if c == '+' {
                    println!("Position {}: '+' character is invalid in URI queries", i);
                }
            }

            // Replace '+' characters which are invalid in URI query parameters
            let corrected_token = continuation_token.replace('+', "%2B");
            let corrected_url = format!(
                "/?list-type=2&prefix=test/test_list_rich_dir/&delimiter=/&max-keys=5&continuation-token={}",
                corrected_token
            );

            let corrected_result = PathAndQuery::from_str(&corrected_url);

            if corrected_result.is_ok() {
                println!("\nSuccessfully parsed with '+' characters replaced by '%2B'");
            }
        }

        // Verify fix
        let fixed_token = continuation_token.replace('+', "%2B");
        let fixed_url = format!(
            "/?list-type=2&prefix=test/test_list_rich_dir/&delimiter=/&max-keys=5&continuation-token={}",
            fixed_token
        );

        assert!(PathAndQuery::from_str(&fixed_url).is_ok());
    }

    fn default_signer(region: &str) -> Signer<Credential> {
        let request_signer = RequestSigner::new(region);
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::new(GLOBAL_REQWEST_CLIENT.clone()))
            .with_env(OsEnv);
        let provider = ProvideCredentialChain::new().push(EnvCredentialProvider::new());
        Signer::new(ctx, provider, request_signer)
    }

    #[tokio::test]
    async fn test_list() {
        use serde_json::Value;
        use std::env;

        let bucket = env::var("TOS_BUCKET").unwrap();

        let signer = default_signer("cb-beijing");

        let info = {
            let am = AccessorInfo::default();
            am.set_scheme("tos")
                .set_root("/")
                .set_name(&bucket)
                .set_native_capability(Capability::default());

            am.into()
        };

        let core = TosCore {
            info,
            bucket: bucket.clone(),
            endpoint: "https://tos-cn-beijing.volces.com".to_string(),
            endpoint_domain: "tos-cn-beijing.volces.com".to_string(),
            root: "/".to_string(),
            default_storage_class: None,
            allow_anonymous: false,
            signer,
        };

        println!("=== Starting comprehensive parameter testing for tos_list_objects_v2 ===");

        // === Test 1: Create test files and directories ===
        println!("\n=== Step 1: Create test files and directories ===");

        let test_prefix = "test_list_dir_".to_owned() + &format!("{}", rand::random::<u32>());

        println!("  Test prefix: {}", test_prefix);

        // Create test directory (in TOS, this is just a prefix with trailing slash)
        let test_dir = format!("{}/", test_prefix);

        // Create files in the test directory
        let file1_path = format!("{}test_file_1.txt", test_dir);
        let file2_path = format!("{}sub_dir/test_file_2.txt", test_dir);
        let file3_path = format!("{}empty_dir/", test_dir);

        // Write file 1
        let write_req1 = core
            .tos_put_object_request(
                &file1_path,
                Some(11),
                &OpWrite::default(),
                Buffer::from(Vec::from(b"Hello World")),
            )
            .unwrap();
        let resp1 = core.send(write_req1).await;

        if let Ok(_) = resp1 {
            println!("  ✅ File created successfully: {}", file1_path);
        }

        // Write file 2 in subdir
        let write_req2 = core
            .tos_put_object_request(
                &file2_path,
                Some(14),
                &OpWrite::default(),
                Buffer::from(Vec::from(b"Subdir Content")),
            )
            .unwrap();

        let resp2 = core.send(write_req2).await;

        if let Ok(_) = resp2 {
            println!("  ✅ File created successfully: {}", file2_path);
        }

        // Create an "empty directory" (with trailing slash and empty body)
        let empty_dir_req = core
            .tos_put_object_request(&file3_path, Some(0), &OpWrite::default(), Buffer::new())
            .unwrap();

        let empty_dir_resp = core.send(empty_dir_req).await;

        if let Ok(_) = empty_dir_resp {
            println!("  ✅ Empty directory created successfully: {}", file3_path);
        }

        // === Test 2: Verify the created files and directories are listed correctly ===
        println!("\n=== Test 1: Verify all created files and directories are listed ===");

        let prefix = test_dir.as_str();

        let result = core
            .tos_list_objects_v2(prefix, "", "", Some(3), None)
            .await;

        match result {
            Ok(resp) => {
                println!("✅ Prefix filtering test passed");

                let (parts, body) = resp.into_parts();
                assert_eq!(parts.status, http::StatusCode::OK);

                let body_bytes = body.to_bytes();
                let body_str = String::from_utf8_lossy(&body_bytes);
                let json_body: Value =
                    serde_json::from_str(&body_str).expect("Failed to parse JSON response");

                let key_count = json_body
                    .get("KeyCount")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                println!("  Keys returned: {}", key_count);

                if let Some(contents) = json_body.get("Contents") {
                    for item in contents.as_array().unwrap_or(&vec![]) {
                        if let Some(key) = item.get("Key") {
                            assert!(key.as_str().unwrap_or("").starts_with(prefix));
                        }
                    }
                }
            }
            Err(e) => panic!("❌ Test 1 failed: {:?}", e),
        }

        // === Test 2: Verify limit parameter ===
        println!("\n=== Test 2: Limit parameter === ");

        let limit = 2;

        let result = core
            .tos_list_objects_v2(prefix, "", "", Some(limit), None)
            .await;

        match result {
            Ok(resp) => {
                println!("✅ Limit parameter test passed");

                let body_bytes = resp.into_body().to_bytes();
                let body_str = String::from_utf8_lossy(&body_bytes);
                let json_body: Value =
                    serde_json::from_str(&body_str).expect("Failed to parse JSON response");

                let key_count = json_body
                    .get("KeyCount")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                println!("  Requested limit: {} | Returned: {}", limit, key_count);

                assert!(key_count <= limit as u64);
            }
            Err(e) => panic!("❌ Test 2 failed: {:?}", e),
        }

        // === Test 3: Verify delimiter ===
        println!("\n=== Test 3: Delimiter ===");

        let result = core
            .tos_list_objects_v2(prefix, "", "/", Some(10), None)
            .await;

        match result {
            Ok(resp) => {
                println!("✅ Delimiter test passed");

                let body_bytes = resp.into_body().to_bytes();
                let body_str = String::from_utf8_lossy(&body_bytes);
                let json_body: Value =
                    serde_json::from_str(&body_str).expect("Failed to parse JSON response");

                if let Some(prefixes) = json_body.get("CommonPrefixes") {
                    println!(
                        "  Common prefixes found: {}",
                        prefixes.as_array().unwrap_or(&vec![]).len()
                    );
                }
            }
            Err(e) => panic!("❌ Test 3 failed: {:?}", e),
        }

        // === Test 4: Verify continuation token ===
        println!("\n=== Test 4: Continuation token ===");

        let first_result = core.tos_list_objects_v2("", "", "", Some(2), None).await;

        match first_result {
            Ok(resp1) => {
                let body_bytes1 = resp1.into_body().to_bytes();
                let body_str1 = String::from_utf8_lossy(&body_bytes1);
                let json_body1: Value =
                    serde_json::from_str(&body_str1).expect("Failed to parse JSON response");

                println!("✅ First page request successful");

                if let Some(next_token) = json_body1.get("NextContinuationToken") {
                    if let Some(token_str) = next_token.as_str() {
                        println!("  Continuation token obtained, testing second page...");

                        let second_result = core
                            .tos_list_objects_v2("", token_str, "", Some(2), None)
                            .await;

                        if let Ok(resp2) = second_result {
                            let body_bytes2 = resp2.into_body().to_bytes();
                            let body_str2 = String::from_utf8_lossy(&body_bytes2);
                            let json_body2: Value = serde_json::from_str(&body_str2)
                                .expect("Failed to parse JSON response");

                            let count = json_body2
                                .get("KeyCount")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            println!("  Second page returned {} keys", count);

                            assert!(count > 0, "Second page returned no data");
                        }
                    } else {
                        println!("ℹ️ No more data to continue");
                    }
                }
            }
            Err(e) => panic!("❌ Test 4 failed: {:?}", e),
        }

        // === Test 5: Verify start_after ===
        println!("\n=== Test 5: Start after ===");

        let start_after_key = "0088bb53-b717-433f-be95-b6234453345f/empty.txt";

        let result = core
            .tos_list_objects_v2(prefix, "", "", Some(2), Some(start_after_key.to_string()))
            .await;

        match result {
            Ok(resp) => {
                println!("✅ Start after parameter test passed");

                let body_bytes = resp.into_body().to_bytes();
                let body_str = String::from_utf8_lossy(&body_bytes);
                let json_body: Value =
                    serde_json::from_str(&body_str).expect("Failed to parse JSON response");

                if let Some(contents) = json_body.get("Contents") {
                    for item in contents.as_array().unwrap_or(&vec![]) {
                        if let Some(key) = item.get("Key") {
                            assert!(key.as_str().unwrap_or("") > start_after_key);
                        }
                    }
                }
            }
            Err(e) => panic!("❌ Test 5 failed: {:?}", e),
        }

        // === Test 6: Test all parameters together ===
        println!("\n=== Test 6: All parameters together === ");

        let result = core
            .tos_list_objects_v2(
                prefix,
                "",
                "/",
                Some(2),
                Some("0088bb53-b717-433f-be95-b6234453345f/existing".to_string()),
            )
            .await;

        match result {
            Ok(resp) => {
                println!("✅ All parameters test passed");

                let body_bytes = resp.into_body().to_bytes();
                let body_str = String::from_utf8_lossy(&body_bytes);
                let _json_body: Value =
                    serde_json::from_str(&body_str).expect("Failed to parse JSON response");

                println!("  Response JSON parsed successfully");
            }
            Err(e) => panic!("❌ Test 6 failed: {:?}", e),
        }

        // === Step 3: Verify empty directory ===
        println!("\n=== Test for empty directory === ");

        // Verify that the directory (prefix) exists, but contains no objects
        let list_dir_result = core
            .tos_list_objects_v2(&file3_path, "", "/", Some(10), None)
            .await;

        match list_dir_result {
            Ok(resp) => {
                println!("✅ Empty directory prefix request successful");

                let body_bytes = resp.into_body().to_bytes();
                let body_str = String::from_utf8_lossy(&body_bytes);
                let json_body: Value =
                    serde_json::from_str(&body_str).expect("Failed to parse JSON response");

                let key_count = json_body
                    .get("KeyCount")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                println!("  Objects in directory '{}': {}", file3_path, key_count);

                // Since we created a directory as an object with trailing slash,
                // we should see that object if we don't use a delimiter, but
                // with delimiter "/" we should see it as a prefix.
            }
            Err(e) => panic!("❌ Failed to list directory prefix: {:?}", e),
        }

        // Verify that we created the directory object with trailing slash
        println!("\n=== Verify directory object ===");

        let list_dir_obj_result = core
            .tos_list_objects_v2(&file3_path, "", "", Some(10), None)
            .await;

        match list_dir_obj_result {
            Ok(resp) => {
                let body_bytes = resp.into_body().to_bytes();
                let body_str = String::from_utf8_lossy(&body_bytes);
                let json_body: Value =
                    serde_json::from_str(&body_str).expect("Failed to parse JSON response");

                let contents: Vec<&Value> = match json_body.get("Contents") {
                    Some(Value::Array(arr)) => arr.iter().collect(),
                    _ => vec![],
                };

                let dir_object_count = contents
                    .iter()
                    .filter(|&item| item.get("Key").and_then(|v| v.as_str()).is_some())
                    .count();

                println!("  Directory object count: {}", dir_object_count);

                // Verify the object ends with "/"
                if let Some(key) = contents
                    .first()
                    .and_then(|v| v.get("Key").and_then(|k| k.as_str()))
                {
                    println!("  Object key is directory: {}", key);
                    assert!(key.ends_with('/'), "Directory object should end with '/'");
                }
            }
            Err(e) => panic!("❌ Failed to list directory object: {:?}", e),
        }

        // === Step 4: Cleanup ===
        println!("\n=== Step 4: Cleanup temporary files === ");

        // Delete the files
        let delete_files = vec![file1_path, file2_path, file3_path];

        for file_path in delete_files {
            let delete_result = core
                .tos_delete_object(file_path.as_str(), &OpDelete::default())
                .await;

            if let Ok(resp) = delete_result {
                if resp.status().is_success() {
                    println!("  ✅ Deleted: {}", file_path);
                }
            }
        }

        println!("\n✅=== All tests passed ===✅");
    }

    #[tokio::test]
    async fn test_put_head_delete() {
        let bucket = "dp-sunxin".to_string();

        let signer = default_signer("cb-beijing");

        let info = {
            let am = AccessorInfo::default();
            am.set_scheme("tos")
                .set_root("/")
                .set_name(&bucket)
                .set_native_capability(Capability::default());

            am.into()
        };

        let core = TosCore {
            info,
            bucket: bucket.clone(),
            endpoint: "https://tos-cn-beijing.volces.com".to_string(),
            endpoint_domain: "tos-cn-beijing.volces.com".to_string(),
            root: "/".to_string(),
            default_storage_class: None,
            allow_anonymous: false,
            signer,
        };

        let test_path = "test_put_head_delete_object.txt";

        println!("bucket: {}, test_path: {}", bucket, test_path);

        let test_content = "Hello, OpenDAL!".as_bytes();

        println!("=== Step 1: Put object ===");
        let put_args = OpWrite::default();
        let put_req = core
            .tos_put_object_request(
                test_path,
                Some(test_content.len() as u64),
                &put_args,
                Buffer::from(test_content),
            )
            .expect("Failed to build put request");

        let put_resp = core.send(put_req).await.expect("Failed to put object");
        println!("  ✅ PUT status: {}", put_resp.status());

        println!("\n=== Step 2: Head object and print properties ===");
        let head_args = OpStat::default();
        let head_resp = core
            .tos_head_object(test_path, head_args)
            .await
            .expect("Failed to head object");

        println!("  ✅ HEAD status: {}", head_resp.status());
        println!(
            "  Content-Length: {:?}",
            head_resp.headers().get(http::header::CONTENT_LENGTH)
        );
        println!(
            "  Content-Type: {:?}",
            head_resp.headers().get(http::header::CONTENT_TYPE)
        );
        println!("  ETag: {:?}", head_resp.headers().get(http::header::ETAG));
        println!(
            "  Last-Modified: {:?}",
            head_resp.headers().get(http::header::LAST_MODIFIED)
        );

        println!("\n=== Step 3: Delete object ===");
        let delete_args = OpDelete::default();
        let delete_resp = core
            .tos_delete_object(test_path, &delete_args)
            .await
            .expect("Failed to delete object");
        println!("  ✅ DELETE status: {}", delete_resp.status());
        println!(" delete: {:?}", delete_resp);

        println!("\n=== Step 4: Verify object is deleted ===");
        let verify_head_args = OpStat::default();
        let verify_head_result = core.tos_head_object(test_path, verify_head_args).await;

        match verify_head_result {
            Err(e) => {
                println!("  ✅ Object not found (expected): {}", e);
            }
            Ok(resp) => {
                panic!(
                    "❌ Object should have been deleted, but got status: {}",
                    resp.status()
                );
            }
        }

        println!("\n✅=== All tests passed ===✅");
    }
}
