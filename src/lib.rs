#[macro_use]
pub extern crate anyhow;

use anyhow::Result;
use async_graphql::types::UploadValue;
use awc::http::{PathAndQuery, Uri};
use data_encoding::HEXLOWER;
use futures_util::stream::TryStreamExt;
use lazy_static::lazy_static;
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use std::{env, time::SystemTime};
use tokio_util::codec;

lazy_static! {
  static ref API_KEY: String =
    env::var("CLOUDINARY_API_KEY").expect("CLOUDINARY_API_KEY env not set");
  static ref API_SECRET: String =
    env::var("CLOUDINARY_API_SECRET").expect("CLOUDINARY_API_SECRET env not set");
  static ref CLOUD_NAME: String =
    env::var("CLOUDINARY_CLOUD_NAME").expect("CLOUDINARY_CLOUD_NAME env not set");
}

pub enum UploadPrivacy {
  Public,
  Private,
}

#[derive(Serialize, Deserialize)]
pub struct UploadRequest {
  api_key: String,
  timestamp: u64,
  signature: String,
}

#[derive(Deserialize)]
pub struct UploadResponse {
  asset_id: String,
}

// 1) Create a string with the parameters used in the POST request to Cloudinary:
// - All parameters added to the method call should be included except: file, cloud_name, resource_type and your api_key.
// - Add the timestamp parameter.
// - Sort all the parameters in alphabetical order.
// - Separate the parameter names from their values with an = and join the parameter/value pairs together with an &.
// 2) Append your API secret to the end of the string.
// 3) Create a hexadecimal message digest (hash value) of the string using an SHA cryptographic function.
fn sign_request(timestamp: u64) -> String {
  let pre_signature = String::from("timestamp=");
  pre_signature.push_str(timestamp.to_string().as_ref());
  pre_signature.push_str(&*API_SECRET);

  let mut context = Context::new(&SHA256);
  context.update(&pre_signature.as_bytes());
  let digest = context.finish();

  HEXLOWER.encode(digest.as_ref())
}

fn generate_upload_endpoint(privacy: &UploadPrivacy) -> Uri {
  let timestamp = SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .unwrap()
    .as_secs();

  let signature = sign_request(timestamp);

  let path_and_query: PathAndQuery = match privacy {
    Public => format!(
      "/v1_1/{}/auto/upload?api_key={}&timestamp={}&signature={}",
      &*CLOUD_NAME,
      &*API_KEY,
      timestamp.to_string(),
      &signature
    ),
    Private => format!(
      "/v1_1/{}/auto/private?api_key={}&timestamp={}&signature={}",
      &*CLOUD_NAME,
      &*API_KEY,
      timestamp.to_string(),
      &signature
    ),
  }
  .parse()
  .unwrap();

  Uri::builder()
    .scheme("https")
    .authority("api.cloudinary.com")
    .path_and_query(path_and_query)
    .build()
    .unwrap()
}

pub async fn upload_media(file: UploadValue, privacy: UploadPrivacy) -> Result<UploadResponse> {
  let uri = generate_upload_endpoint(&privacy);

  let upload = file.into_async_read();

  let stream =
    codec::FramedRead::new(upload.into(), codec::BytesCodec::new()).map_ok(|bytes| bytes.freeze());

  let mut client = awc::Client::new();

  let response = client
    .post(uri)
    .send_stream(stream)
    .await
    .map_err(|e| anyhow!(e.to_string()))?;

  let data = response.json::<UploadResponse>().await?;

  Ok(data)
}
