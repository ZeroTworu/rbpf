fn main()  {
    println!("cargo:warning=Compiling for: {}", std::env::var("CARGO_CFG_TARGET_ARCH").unwrap());
}
