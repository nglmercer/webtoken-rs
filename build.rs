fn main() {
    #[cfg(feature = "napi-base")]
    {
        extern crate napi_build;
        napi_build::setup();
    }
}
