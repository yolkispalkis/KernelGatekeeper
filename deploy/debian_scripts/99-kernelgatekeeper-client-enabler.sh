if command -v systemctl >/dev/null && [ -n "$XDG_RUNTIME_DIR" ]; then
    if systemctl --user list-unit-files kernelgatekeeper-client.service >/dev/null 2>&1 \
        && ! systemctl --user is-enabled --quiet kernelgatekeeper-client.service 2>/dev/null; then
        echo "KernelGatekeeper: Enabling user client service (first time setup via profile.d)..." >&2
        systemctl --user enable --now kernelgatekeeper-client.service >/dev/null 2>&1
    fi
fi
