%global debug_package %{nil}
%global selinux_type   targeted
%global selinux_mod    pam_nps_mfa
# The cdylib crate-name is pam_nps_mfa, so cargo emits libpam_nps_mfa.so.
# The installed PAM module MUST be pam_nps_mfa.so (lib prefix stripped).
%global built_so       libpam_nps_mfa.so
%global installed_so   pam_nps_mfa.so

Name:           pam_nps_mfa
Version:        0.1.0
Release:        1%{?dist}
Summary:        PAM module bridging Linux logins to Microsoft NPS for Entra-backed MFA over RADIUS

License:        MIT
URL:            https://github.com/rupivbluegreen/pam_nps_mfa
Source0:        %{name}-%{version}.tar.gz

# RHEL9 / x86_64: _libdir = /usr/lib64, SELinux type = targeted.
ExclusiveArch:  x86_64

# Toolchain to build the workspace cdylib and the SELinux policy module.
BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  pam-devel
BuildRequires:  audit-libs-devel
BuildRequires:  selinux-policy-devel
BuildRequires:  make

# Runtime libraries the module links (-lpam -laudit, from crates/pam-ffi/build.rs).
Requires:       pam
Requires:       audit-libs
Requires:       selinux-policy-%{selinux_type}

# semodule / restorecon live in policycoreutils and are needed by the scriptlets.
Requires(post):   policycoreutils
Requires(postun): policycoreutils

%description
pam_nps_mfa is a Rust PAM authentication module that turns a Linux host into a
hardened RADIUS client for Microsoft NPS, so an NPS deployment with the Entra
MFA extension can gate local and SSH logins with a second factor. It supports
MSCHAPv2 (push/phone) and PAP (full Entra method set incl. TOTP via
Access-Challenge), fails closed on any error, and enforces Message-Authenticator
on every request (post-BlastRADIUS).

CAVEATS (read before deploying — SECURITY_DESIGN §9):
 * IPsec is a REQUIRED control, not optional. MSCHAPv2 and PAP attributes travel
   in the clear inside the RADIUS packet; only an ESP tunnel between this host
   and NPS removes the on-path capture risk. Do not run on a bare wire.
 * Active Directory Protected Users CANNOT authenticate with MSCHAPv2 (the group
   disables the NTLM path MSCHAPv2 depends on). Privileged admins are the most
   likely to be in Protected Users AND to need MFA here — confirm target
   accounts are not in Protected Users, or give them a different primary-auth
   path, before committing to MSCHAPv2.
 * Public-key and GSSAPI SSH auth skip PAM entirely. Apply the shipped
   sshd_config snippet (AuthenticationMethods + KbdInteractiveAuthentication) or
   the second factor will not be enforced. A break-glass reference is shipped.

%prep
%setup -q

%build
# Offline/vendored is nicer but not required for the gate; a plain build that
# resolves crates.io is acceptable. Keep cargo's state inside the build tree so
# it never touches a real $HOME.
export CARGO_HOME=%{_builddir}/%{name}-%{version}/.cargo
# Link flags come from crates/pam-ffi/build.rs (-lpam -laudit); do not hand-hack
# linker paths here.
cargo build --release --locked

# Compile the SELinux policy module (.pp) from the shipped .te/.fc/.if. The
# refpolicy devel Makefile is invoked from within the policy source dir.
make -C packaging/selinux -f %{_datadir}/selinux/devel/Makefile %{selinux_mod}.pp

%install
# --- PAM module: strip the lib prefix on install (libpam_nps_mfa.so -> pam_nps_mfa.so)
install -d -m 0755 %{buildroot}%{_libdir}/security
install -m 0755 target/release/%{built_so} \
    %{buildroot}%{_libdir}/security/%{installed_so}

# --- Live config tree ------------------------------------------------------
install -d -m 0755 %{buildroot}%{_sysconfdir}/pam_nps
install -m 0600 packaging/dist/pam_nps.conf.sample \
    %{buildroot}%{_sysconfdir}/pam_nps/pam_nps.conf
# secret.d/ dir is 0700 root:root; ship only a 0600 documentation README in it
# (NOT a real secret, and NOT world-readable).
install -d -m 0700 %{buildroot}%{_sysconfdir}/pam_nps/secret.d
install -m 0600 packaging/dist/secret.d-README \
    %{buildroot}%{_sysconfdir}/pam_nps/secret.d/README

# --- SELinux policy module -------------------------------------------------
install -d -m 0755 %{buildroot}%{_datadir}/selinux/packages
install -m 0644 packaging/selinux/%{selinux_mod}.pp \
    %{buildroot}%{_datadir}/selinux/packages/%{selinux_mod}.pp

# Reference deployment snippets + SELinux sources are shipped as %doc — listed
# in %files with build-relative source paths, so rpmbuild copies them into
# %{_docdir}/%{name}/ and owns that directory automatically (nothing unowned).

%post
# Load the policy module and relabel the config tree. Guarded on a live SELinux
# kernel: in a build container selinuxenabled is false and this is a clean
# no-op (real load is deferred to a RHEL9 host — phase 9). When SELinux IS
# enabled, a semodule failure is NOT silently ignored: it exits non-zero so rpm
# surfaces the scriptlet error.
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
    semodule -n -i %{_datadir}/selinux/packages/%{selinux_mod}.pp || exit 1
    /usr/sbin/load_policy || :
    /usr/sbin/restorecon -R %{_sysconfdir}/pam_nps || :
fi

%postun
# Unload only on final erase ($1 == 0), never on upgrade.
if [ $1 -eq 0 ]; then
    if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
        semodule -n -r %{selinux_mod} 2>/dev/null || :
        /usr/sbin/load_policy || :
    fi
fi

%files
%license LICENSE
%doc README.md
%doc packaging/dist/pam.d-sshd.snippet
%doc packaging/dist/sshd_config.snippet
%doc packaging/dist/pam_nps.conf.sample
%doc packaging/dist/secret.d-README
%doc packaging/selinux/%{selinux_mod}.te
%doc packaging/selinux/%{selinux_mod}.fc
%doc packaging/selinux/%{selinux_mod}.if
%doc docs/phase9-nps-validation.md
# The PAM module: 0755 root:root in the platform security dir.
%attr(0755,root,root) %{_libdir}/security/%{installed_so}
# Config tree — nothing left unowned.
%dir %attr(0755,root,root) %{_sysconfdir}/pam_nps
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/pam_nps/pam_nps.conf
%dir %attr(0700,root,root) %{_sysconfdir}/pam_nps/secret.d
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/pam_nps/secret.d/README
# SELinux policy package file.
%attr(0644,root,root) %{_datadir}/selinux/packages/%{selinux_mod}.pp

%changelog
* Fri Jul 03 2026 rupivbluegreen <arunbharadwaj13@gmail.com> - 0.1.0-1
- Initial RHEL9 packaging: cdylib -> /usr/lib64/security/pam_nps_mfa.so,
  0600 root:root config under /etc/pam_nps, 0700 secret.d/, targeted SELinux
  policy module (radius_port_t + dedicated pam_nps_conf_t + audit), reference
  pam.d/sshd snippets. Phase 9 real-NPS validation still required.
