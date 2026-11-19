// SPDX-License-Identifier: MIT
use enzimos_installer::desktop_policy as policy;
#[test]
fn preserves_vendor_authentication_admin_keyring_and_input_method_defaults() {
    let vendor = "auth include system-login\nsession include system-login\n";
    let managed = policy::pam(vendor, "greetd").unwrap();
    assert!(managed.starts_with(vendor));
    assert_eq!(policy::pam(&managed, "greetd").unwrap(), managed);
    assert!(managed.contains("pam_succeed_if.so user = greeter"));
    let admin = format!("{vendor}auth optional pam_oo7.so\n");
    let configured = policy::pam(&admin, "greetd").unwrap();
    assert!(configured.starts_with(&admin));
    assert!(configured.contains("password include system-local-login"));
    assert_eq!(policy::pam(&configured, "greetd").unwrap(), configured);
    let custom = format!("{admin}password requisite pam_custom.so\n");
    assert_eq!(policy::pam(&custom, "greetd").unwrap(), custom);
    assert!(policy::pam("auth optional pam_permit.so\n", "greetd").is_err());
    assert!(
        policy::pam(
            &format!("{vendor}# END enzimOS desktop integration\n"),
            "greetd"
        )
        .is_err()
    );
    assert!(policy::pam(vendor, "unknown").is_err());
    let env = "export\tQT_IM_MODULE=custom\nGTK_IM_MODULE=native\n";
    let env = policy::environment(env).unwrap();
    assert!(env.contains("QT_IM_MODULE=custom"));
    assert!(!env.contains("QT_IM_MODULE=fcitx"));
    assert_eq!(policy::environment(&env).unwrap(), env);
}
#[test]
fn validates_real_authorization_scope_balanced_sections_and_unique_ini_keys() {
    let vendor = "Listen localhost:631\nBrowsing On\n<Policy default>\n <Limit All>\n  Require user @SYSTEM\n </Limit>\n</Policy>\n";
    let prepared = policy::cups(vendor).unwrap();
    assert!(prepared.contains("Require user @SYSTEM"));
    assert!(prepared.contains("Listen 127.0.0.1:631\n"));
    assert!(prepared.contains("Browsing No\n"));
    assert_eq!(policy::cups(&prepared).unwrap(), prepared);
    assert!(policy::cups(&vendor.replace("</Limit>", "</Location>")).is_err());
    assert!(policy::cups(&format!("Port 631\n{vendor}")).is_err());
    assert!(policy::cups("Require user @SYSTEM\n<Policy default>\n</Policy>\n").is_err());
    let avahi =
        policy::avahi("[server]\nhost-name=admin-name\n[reflector]\nenable-reflector=yes\n")
            .unwrap();
    assert!(avahi.contains("host-name=admin-name"));
    assert!(avahi.contains("enable-reflector=no"));
    assert!(!avahi.contains("enable-reflector=yes"));
    assert_eq!(policy::avahi(&avahi).unwrap(), avahi);
    assert!(policy::avahi("[server]\nhost-name=a\nHost-Name=b\n").is_err());
    assert!(policy::avahi("[server]\n[server]\n").is_err());
    let ipp =
        policy::ipp_usb("[network]\ninterface=all # vendor\n[logging]\nmain-log=debug\n").unwrap();
    assert!(ipp.contains("interface=loopback"));
    assert!(ipp.contains("config=@wheel"));
    assert!(ipp.contains("main-log=error"));
}
