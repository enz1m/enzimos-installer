-- SPDX-License-Identifier: MIT
-- Installer kiosk compositor: the enzUI wallpaper and the installer window, nothing else.
-- Closing the installer ends the compositor.
-- Scale 1 until start: Hyprland's "auto" divides by the panel's reported size, and panels
-- that report none (common on older laptops) come out at 2x with the window off-screen.
hl.monitor({ output = "", mode = "preferred", position = "auto", scale = 1 })
hl.env("XCURSOR_SIZE", "24")
hl.env("HYPRCURSOR_SIZE", "24")
hl.config({
    general = { gaps_in = 0, gaps_out = 0, border_size = 0 },
    decoration = {
        rounding = 14,
        blur = { enabled = false },
        shadow = { enabled = true, range = 40, render_power = 3, color = "rgba(00000070)" },
    },
    animations = { enabled = true },
    misc = {
        disable_hyprland_logo = true,
        -- Kiosk lifecycle belongs to systemd/greetd; no desktop helper dialogs.
        disable_watchdog_warning = true, disable_hyprland_guiutils_check = true, disable_splash_rendering = true, force_default_wallpaper = 0,
        background_color = 0xff15171c,
    },
    ecosystem = { no_update_news = true, no_donation_nag = true },
})
hl.layer_rule({ name = "installer-wallpaper", match = { namespace = "^enzui-wallpaper$" }, no_anim = true })
hl.window_rule({
    name = "installer-window", match = { class = "^org[.]enzimos[.]Installer$" },
    float = true, center = true, size = "1080 740", decorate = false,
})
-- The largest scale that keeps a 1280x800 logical desktop and an exact logical size;
-- 1 for anything smaller. Chosen from pixels alone, never from the reported panel size.
local function kiosk_scale(width, height)
    for _, scale in ipairs({ 2, 1.6, 1.5, 1.25 }) do
        local w, h = width / scale, height / scale
        if w >= 1280 and h >= 800 and w == math.floor(w) and h == math.floor(h) then
            return scale
        end
    end
    return 1
end
hl.on("hyprland.start", function()
    -- Floating windows must fit the logical output, including small VM displays.
    local monitors = hl.get_monitors()
    local monitor = monitors[1]
    if monitor then
        local scale = kiosk_scale(monitor.width, monitor.height)
        for _, m in ipairs(monitors) do
            local s = kiosk_scale(m.width, m.height)
            if s ~= 1 then
                hl.monitor({ output = m.name, mode = "preferred", position = "auto", scale = s })
            end
        end
        local width = math.floor(math.min(1080, monitor.width / scale))
        local height = math.floor(math.min(740, monitor.height / scale))
        hl.window_rule({ name = "installer-window", match = { class = "^org[.]enzimos[.]Installer$" },
            float = true, center = true, size = string.format("%d %d", width, height), decorate = false })
    end
    hl.exec_cmd("/usr/bin/enzui-wallpaper 15171c fill /usr/share/enzui/assets/wallpapers/enzui-aurora.jpg fade")
    hl.exec_cmd("/usr/bin/enzimos-installer $ENZIMOS_INSTALLER_ARGS; hyprctl dispatch 'hl.dsp.exit()'")
end)
