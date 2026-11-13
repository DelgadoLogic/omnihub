using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace OmniHub.App.Interop;

/// <summary>
/// Pure Win32 system tray icon (Shell_NotifyIconW) and global Alt+Space hotkey (RegisterHotKey)
/// hosted on a lightweight HwndSource message sink with zero System.Windows.Forms dependency.
/// </summary>
public sealed class Win32TrayAndHotkeyService : IDisposable
{
    private const int WM_HOTKEY = 0x0312;
    private const int WM_TRAYICON = 0x8000 + 0x44;
    private const int WM_LBUTTONUP = 0x0202;
    private const int WM_LBUTTONDBLCLK = 0x0203;
    private const int WM_RBUTTONUP = 0x0205;
    private const int WM_CONTEXTMENU = 0x007B;

    private const uint MOD_ALT = 0x0001;
    private const uint MOD_NOREPEAT = 0x4000;
    private const uint VK_SPACE = 0x20;
    private const int HOTKEY_ID_ALT_SPACE = 0x4F48; // 'OH'

    private const uint NIM_ADD = 0x00000000;
    private const uint NIM_MODIFY = 0x00000001;
    private const uint NIM_DELETE = 0x00000002;
    private const uint NIF_MESSAGE = 0x00000001;
    private const uint NIF_ICON = 0x00000002;
    private const uint NIF_TIP = 0x00000004;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATAW
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public uint uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ICONINFO
    {
        public bool fIcon;
        public int xHotspot;
        public int yHotspot;
        public IntPtr hbmMask;
        public IntPtr hbmColor;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BITMAPINFOHEADER
    {
        public uint biSize;
        public int biWidth;
        public int biHeight;
        public ushort biPlanes;
        public ushort biBitCount;
        public uint biCompression;
        public uint biSizeImage;
        public int biXPelsPerMeter;
        public int biYPelsPerMeter;
        public uint biClrUsed;
        public uint biClrImportant;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool Shell_NotifyIconW(uint dwMessage, ref NOTIFYICONDATAW lpdata);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnregisterHotKey(IntPtr hWnd, int id);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr CreateIconIndirect(ref ICONINFO icon);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr CreateDIBSection(
        IntPtr hdc,
        ref BITMAPINFOHEADER pbmi,
        uint iUsage,
        out IntPtr ppvBits,
        IntPtr hSection,
        uint dwOffset);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr CreateBitmap(int nWidth, int nHeight, uint cPlanes, uint cBitsPerPel, IntPtr lpvBits);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool DeleteObject(IntPtr hObject);

    private HwndSource? _hwndSource;
    private IntPtr _hIcon;
    private bool _trayAdded;
    private bool _disposed;

    public bool IsHotkeyRegistered { get; private set; }
    public string HotkeyStatusDescription { get; private set; } = "Alt+Space (Initializing)";

    public event EventHandler? GlobalHotkeyPressed;
    public event EventHandler? TrayOpenRequested;
    public event EventHandler<Point>? TrayContextMenuRequested;

    public void Initialize(string tooltip = "DelgadoLogic OmniHub — Alt+Space Quick Launcher")
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_hwndSource is not null) return;

        var parameters = new HwndSourceParameters("DelgadoLogicOmniHubMessageSink")
        {
            Width = 0,
            Height = 0,
            PositionX = 0,
            PositionY = 0,
            WindowStyle = 0
        };

        _hwndSource = new HwndSource(parameters);
        _hwndSource.AddHook(WndProc);

        _hIcon = CreateBrandHIcon(32);

        var nid = new NOTIFYICONDATAW
        {
            cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
            hWnd = _hwndSource.Handle,
            uID = 1,
            uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage = WM_TRAYICON,
            hIcon = _hIcon,
            szTip = tooltip.Length > 120 ? tooltip[..120] : tooltip,
            szInfo = "",
            szInfoTitle = ""
        };

        _trayAdded = Shell_NotifyIconW(NIM_ADD, ref nid);

        IsHotkeyRegistered = RegisterHotKey(
            _hwndSource.Handle,
            HOTKEY_ID_ALT_SPACE,
            MOD_ALT | MOD_NOREPEAT,
            VK_SPACE);

        HotkeyStatusDescription = IsHotkeyRegistered
            ? "Active — Global Alt+Space registered (Ctrl+K also active in-app)"
            : "In-App Ctrl+K Active (Alt+Space currently held by another desktop utility)";
    }

    public void UpdateTooltip(string tooltip)
    {
        if (!_trayAdded || _hwndSource is null) return;
        var nid = new NOTIFYICONDATAW
        {
            cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
            hWnd = _hwndSource.Handle,
            uID = 1,
            uFlags = NIF_TIP,
            szTip = tooltip.Length > 120 ? tooltip[..120] : tooltip,
            szInfo = "",
            szInfoTitle = ""
        };
        Shell_NotifyIconW(NIM_MODIFY, ref nid);
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_HOTKEY && wParam.ToInt32() == HOTKEY_ID_ALT_SPACE)
        {
            handled = true;
            GlobalHotkeyPressed?.Invoke(this, EventArgs.Empty);
            return IntPtr.Zero;
        }

        if (msg == WM_TRAYICON)
        {
            int mouseMsg = (int)(lParam.ToInt64() & 0xFFFF);
            if (mouseMsg is WM_LBUTTONDBLCLK or WM_LBUTTONUP)
            {
                handled = true;
                TrayOpenRequested?.Invoke(this, EventArgs.Empty);
            }
            else if (mouseMsg is WM_RBUTTONUP or WM_CONTEXTMENU)
            {
                handled = true;
                GetCursorPos(out var pt);
                TrayContextMenuRequested?.Invoke(this, new Point(pt.X, pt.Y));
            }
        }

        return IntPtr.Zero;
    }

    /// <summary>
    /// Generates a crisp 32-bpp BGRA ImageSource for Window.Icon matching the system tray icon.
    /// </summary>
    public static BitmapSource CreateBrandWindowIcon(int size = 64)
    {
        var pixels = RenderBrandIconBgra(size);
        var bmp = BitmapSource.Create(
            size,
            size,
            96,
            96,
            PixelFormats.Bgra32,
            null,
            pixels,
            size * 4);
        bmp.Freeze();
        return bmp;
    }

    private static IntPtr CreateBrandHIcon(int size)
    {
        var pixels = RenderBrandIconBgra(size);
        var bmi = new BITMAPINFOHEADER
        {
            biSize = (uint)Marshal.SizeOf<BITMAPINFOHEADER>(),
            biWidth = size,
            biHeight = -size, // Top-down DIB
            biPlanes = 1,
            biBitCount = 32,
            biCompression = 0
        };

        IntPtr hbmColor = CreateDIBSection(IntPtr.Zero, ref bmi, 0, out IntPtr bits, IntPtr.Zero, 0);
        if (hbmColor == IntPtr.Zero || bits == IntPtr.Zero)
            return IntPtr.Zero;

        Marshal.Copy(pixels, 0, bits, pixels.Length);
        IntPtr hbmMask = CreateBitmap(size, size, 1, 1, IntPtr.Zero);

        try
        {
            var ii = new ICONINFO
            {
                fIcon = true,
                hbmColor = hbmColor,
                hbmMask = hbmMask
            };
            return CreateIconIndirect(ref ii);
        }
        finally
        {
            if (hbmColor != IntPtr.Zero) DeleteObject(hbmColor);
            if (hbmMask != IntPtr.Zero) DeleteObject(hbmMask);
        }
    }

    private static byte[] RenderBrandIconBgra(int size)
    {
        var buf = new byte[size * size * 4];
        double center = (size - 1) / 2.0;
        double outerRadius = size * 0.46;
        double innerRingOuter = size * 0.28;
        double innerRingInner = size * 0.14;

        for (int y = 0; y < size; y++)
        {
            for (int x = 0; x < size; x++)
            {
                int idx = ((y * size) + x) * 4;
                double dx = x - center;
                double dy = y - center;

                // Superellipse (squircle) container + glowing cyan-to-purple ring
                double normX = Math.Abs(dx) / outerRadius;
                double normY = Math.Abs(dy) / outerRadius;
                double squircle = Math.Pow(normX, 3.2) + Math.Pow(normY, 3.2);

                if (squircle > 1.0)
                {
                    buf[idx + 3] = 0;
                    continue;
                }

                double t = (x + y) / (double)(2 * size);
                byte accentR = (byte)(0 + (147 * t));     // #00E5FF -> #9333EA
                byte accentG = (byte)(229 - (178 * t));
                byte accentB = (byte)(255 - (21 * t));

                double dist = Math.Sqrt((dx * dx) + (dy * dy));
                bool isRing = dist >= innerRingInner && dist <= innerRingOuter;
                bool isBorder = squircle > 0.84;

                if (isRing || isBorder)
                {
                    buf[idx + 0] = accentB;
                    buf[idx + 1] = accentG;
                    buf[idx + 2] = accentR;
                    buf[idx + 3] = 255;
                }
                else
                {
                    buf[idx + 0] = 26; // Deep obsidian fill #0B101A
                    buf[idx + 1] = 16;
                    buf[idx + 2] = 11;
                    buf[idx + 3] = 255;
                }
            }
        }
        return buf;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (_hwndSource is not null)
        {
            if (IsHotkeyRegistered)
            {
                UnregisterHotKey(_hwndSource.Handle, HOTKEY_ID_ALT_SPACE);
                IsHotkeyRegistered = false;
            }

            if (_trayAdded)
            {
                var nid = new NOTIFYICONDATAW
                {
                    cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
                    hWnd = _hwndSource.Handle,
                    uID = 1
                };
                Shell_NotifyIconW(NIM_DELETE, ref nid);
                _trayAdded = false;
            }

            _hwndSource.RemoveHook(WndProc);
            _hwndSource.Dispose();
            _hwndSource = null;
        }

        if (_hIcon != IntPtr.Zero)
        {
            DestroyIcon(_hIcon);
            _hIcon = IntPtr.Zero;
        }
    }
}
