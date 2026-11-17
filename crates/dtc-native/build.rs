use std::{env, fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out.join("version_gen.h"), "#define DTC_VERSION \"1.8.1\"\n").unwrap();
    println!("cargo:rerun-if-changed=vendor/dtc");
    println!("cargo:rerun-if-changed=generated");

    let dtc = "vendor/dtc";
    cc::Build::new()
        .include(dtc)
        .include(format!("{dtc}/libfdt"))
        .include("generated")
        .include(&out)
        .define("NO_YAML", None)
        // dtc is only ever entered through `bootimg_dtc_main` in a dedicated process.
        .define("main", "bootimg_dtc_main")
        .flag_if_supported("-std=gnu11")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-sign-compare")
        .flag_if_supported("-Wno-missing-field-initializers")
        .files(
            [
                "dtc.c",
                "checks.c",
                "data.c",
                "flattree.c",
                "fstree.c",
                "livetree.c",
                "srcpos.c",
                "treesource.c",
                "util.c",
            ]
            .map(|file| format!("{dtc}/{file}")),
        )
        .files(["generated/dtc-parser.tab.c", "generated/dtc-lexer.lex.c"])
        .compile("dtc");
}
