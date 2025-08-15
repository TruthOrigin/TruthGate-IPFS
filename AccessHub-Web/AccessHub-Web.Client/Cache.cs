using MudBlazor;

namespace TruthGate_Web.Client
{
    public static class Cache
    {
        public static MudTheme CustomTheme = new()
        {
            PaletteLight = new()
            {
                Primary = "#2D2A5A",          // Deep Indigo
                Secondary = "#00E3C0",        // Electric Mint
                Black = "#110e2d",
                AppbarText = "#424242",
                AppbarBackground = "rgba(255,255,255,0.8)",
                DrawerBackground = "#ffffff",
                GrayLight = "#e8e8e8",
                GrayLighter = "#f9f9f9",
            },
            PaletteDark = new()
            {
                Primary = "#00E3C0",          // Electric Mint now the star
                PrimaryContrastText = "#000000",
                Secondary = "#3C3970",        // Softer indigo accent (less oppressive than deep indigo)
                Background = "#1E1F22",       // Discord-ish near-black with a whisper of warmth
                Surface = "#2B2D31",          // Elevated panels (matches Discord card tone)
                DrawerBackground = "#232428", // Sidebar tone
                AppbarBackground = "#1B1C1F", // Slightly darker than background for separation
                AppbarText = "#E0E0E0",       // Soft but high-contrast
                TextPrimary = "#FFFFFF",      // True white for legibility
                TextSecondary = "#A3A6AA",    // Muted gray
                ActionDefault = "#00E3C0",    // Same as primary for cohesion
                Divider = "#383A40"           // Subtle panel separators
            },
            LayoutProperties = new LayoutProperties()
        };
    }
}
