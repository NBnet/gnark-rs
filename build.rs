fn main() {
    rust2go::Builder::new()
        .with_go_src("./go")
        .with_regen("./src/gnark.rs", "./go/gen.go")
        .build();
}
