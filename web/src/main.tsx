import { StrictMode, useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertCircle,
  Archive,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Copy,
  Database,
  Download,
  Eye,
  EyeOff,
  FileKey2,
  Filter,
  Laptop,
  LogOut,
  Menu,
  Pause,
  Play,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Smartphone,
  Terminal,
  Trash2,
  Wifi,
  X,
} from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import "./styles.css";
import {
  filenameFromDisposition,
  formatBytes,
  formatDate,
  formatTime,
} from "./utils";

type Flow = {
  id: string;
  captureId: string;
  sessionId: string;
  protocol: string;
  method?: string;
  host: string;
  path?: string;
  status?: number;
  requestContentType?: string;
  responseContentType?: string;
  requestBytes: number;
  responseBytes: number;
  startedAt: string;
  completedAt?: string;
  durationMs?: number;
  state: "loading" | "complete" | "error";
  errorCode?: string;
  notCapturedReason?: string;
  websocket?: boolean;
};

type FlowDetail = Flow & {
  raw: boolean;
  url: string;
  query: string[][];
  requestHeaders: string[][];
  responseHeaders: string[][];
};

type BodyPreview = {
  state: string;
  encoding: string;
  content: string;
  contentType?: string;
  view: string;
  raw: boolean;
  truncated: boolean;
};

type WebSocketMessage = {
  id: string;
  sequence: number;
  fromClient: boolean;
  opcode: number;
  payloadSize: number;
  timestamp: string;
  payload: BodyPreview;
};

type DeviceProfile = {
  deviceId: string;
  name: string;
  profile: string;
  peerPublicKey: string;
  tunnelIp?: string | null;
  filename: string;
};

type Session = {
  id: string;
  name: string;
  startedAt: string;
  flowCount: number;
  bytes: number;
};

type Device = {
  id: string;
  name: string;
  tunnelIp?: string | null;
  revokedAt?: string | null;
};

type SystemOverview = {
  recordedBodyBytes?: number;
  disk?: { free?: number };
  spooledEvents?: number;
  droppedEvents?: number;
};

type AuditEntry = {
  id: string;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  sourceIp?: string | null;
  createdAt: string;
};

type ReauthAction =
  | "reveal"
  | "raw-export"
  | "download-request"
  | "download-response";
type PageId = "live" | "sessions" | "devices" | "system";

const methodClasses: Record<string, string> = {
  GET: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
  POST: "bg-violet-50 text-violet-700 ring-violet-600/20",
  PUT: "bg-amber-50 text-amber-700 ring-amber-600/20",
  PATCH: "bg-orange-50 text-orange-700 ring-orange-600/20",
  DELETE: "bg-rose-50 text-rose-700 ring-rose-600/20",
  CONNECT: "bg-sky-50 text-sky-700 ring-sky-600/20",
};

const stateClasses: Record<Flow["state"], string> = {
  complete: "text-emerald-700",
  error: "text-rose-700",
  loading: "text-amber-700",
};

const panelClass = "rounded-2xl border border-slate-200 bg-white shadow-sm";
const buttonBase =
  "inline-flex min-h-10 items-center justify-center gap-2 rounded-xl px-3.5 text-sm font-semibold transition focus-visible:outline-none focus-visible:ring-4 disabled:cursor-wait disabled:opacity-60";
const primaryButton = `${buttonBase} bg-emerald-600 text-white shadow-sm shadow-emerald-600/20 hover:bg-emerald-700 focus-visible:ring-emerald-600/20`;
const secondaryButton = `${buttonBase} border border-slate-200 bg-white text-slate-700 shadow-sm hover:border-emerald-200 hover:bg-emerald-50 hover:text-emerald-700 focus-visible:ring-emerald-600/15`;
const iconButton =
  "inline-grid size-10 shrink-0 place-items-center rounded-xl text-slate-500 transition hover:bg-slate-100 hover:text-slate-800 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-emerald-600/15";
const inputClass =
  "h-11 w-full rounded-xl border border-slate-200 bg-white px-3.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-emerald-500 focus:ring-4 focus:ring-emerald-500/10";
const labelClass = "grid gap-2 text-sm font-medium text-slate-700";

const navItems: { id: PageId; label: string; icon: typeof Activity }[] = [
  { id: "live", label: "Theo dõi trực tiếp", icon: Activity },
  { id: "sessions", label: "Phiên đã lưu", icon: Archive },
  { id: "devices", label: "Thiết bị & cài đặt", icon: Smartphone },
  { id: "system", label: "Hệ thống & nhật ký", icon: Server },
];

function cn(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(" ");
}

function useMediaQuery(query: string) {
  const [matches, setMatches] = useState(() =>
    typeof window === "undefined" ? false : window.matchMedia(query).matches,
  );

  useEffect(() => {
    const media = window.matchMedia(query);
    const update = () => setMatches(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, [query]);

  return matches;
}

function csrfHeaders(init: RequestInit) {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("content-type"))
    headers.set("content-type", "application/json");
  if (!["GET", "HEAD"].includes(init.method || "GET")) {
    const csrf = document.cookie
      .split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith("mti_csrf="))
      ?.split("=")[1];
    if (csrf) headers.set("X-CSRF-Token", decodeURIComponent(csrf));
  }
  return headers;
}

const api = {
  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(path, {
      ...init,
      headers: csrfHeaders(init),
      credentials: "include",
    });
    if (!response.ok) {
      if (response.status === 401)
        window.dispatchEvent(new Event("mti:unauthenticated"));
      const detail = await response.json().catch(() => ({}));
      throw new Error(detail.detail || `Yêu cầu thất bại (${response.status})`);
    }
    if (response.status === 204) return undefined as T;
    return response.json() as Promise<T>;
  },
  flows: (query = "") => api.request<{ items: Flow[] }>(`/api/flows${query}`),
  flow: (id: string, token?: string) =>
    api.request<FlowDetail>(
      `/api/flows/${id}`,
      token ? { headers: { "X-Reveal-Token": token } } : {},
    ),
  body: (id: string, direction: string, token?: string) =>
    api.request<BodyPreview>(
      `/api/flows/${id}/body/${direction}`,
      token ? { headers: { "X-Reveal-Token": token } } : {},
    ),
  websocket: (id: string, token?: string) =>
    api.request<{ items: WebSocketMessage[] }>(
      `/api/flows/${id}/websocket`,
      token ? { headers: { "X-Reveal-Token": token } } : {},
    ),
  async file(path: string, init: RequestInit = {}) {
    const response = await fetch(path, {
      ...init,
      headers: csrfHeaders(init),
      credentials: "include",
    });
    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      throw new Error(detail.detail || `Yêu cầu thất bại (${response.status})`);
    }
    return {
      blob: await response.blob(),
      filename: filenameFromDisposition(
        response.headers.get("content-disposition"),
        "capture.bin",
      ),
    };
  },
  sessions: () => api.request<Session[]>("/api/sessions"),
  deleteSession: (id: string) =>
    api.request<void>(`/api/sessions/${id}`, { method: "DELETE" }),
  devices: () => api.request<Device[]>("/api/devices"),
  createDeviceProfile: (name: string) =>
    api.request<DeviceProfile>("/api/devices/profile", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),
  revokeDevice: (id: string) =>
    api.request<{ revoked: boolean }>(`/api/devices/${id}/revoke`, {
      method: "POST",
    }),
  system: () => api.request<SystemOverview>("/api/system"),
  audit: () => api.request<AuditEntry[]>("/api/audit"),
};

function BrandMark({ small = false }: { small?: boolean }) {
  return (
    <span
      className={cn(
        "grid shrink-0 place-items-center rounded-2xl bg-emerald-600 text-white shadow-sm shadow-emerald-600/25",
        small ? "size-10" : "size-12",
      )}
    >
      <ShieldCheck size={small ? 20 : 25} strokeWidth={2.2} />
    </span>
  );
}

function Login({ onLogin }: { onLogin: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.request("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username: "admin", password }),
      });
      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể đăng nhập");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="relative grid min-h-screen place-items-center overflow-hidden bg-slate-50 px-5 py-10">
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-72 bg-gradient-to-b from-emerald-100/70 to-transparent"
        aria-hidden="true"
      />
      <section className="relative w-full max-w-md rounded-3xl border border-slate-200 bg-white p-7 shadow-xl shadow-slate-900/5 sm:p-9">
        <BrandMark />
        <p className="mt-7 text-xs font-bold uppercase tracking-[0.18em] text-emerald-700">
          Quản trị hệ thống tự lưu trữ
        </p>
        <h1 className="mt-2 text-2xl font-bold tracking-tight text-slate-950">
          Mobile Traffic Inspector
        </h1>
        <p className="mt-2 text-sm leading-6 text-slate-500">
          Đăng nhập để kiểm tra lưu lượng từ các thiết bị đã được bạn cho phép.
        </p>
        <form className="mt-7 grid gap-5" onSubmit={submit}>
          <label className={labelClass}>
            Mật khẩu quản trị
            <input
              className={inputClass}
              autoFocus
              autoComplete="current-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              minLength={12}
              required
            />
          </label>
          {error && <InlineError message={error} />}
          <button className={cn(primaryButton, "w-full")} disabled={busy}>
            {busy ? (
              <RefreshCw className="animate-spin" size={17} />
            ) : (
              <ShieldCheck size={17} />
            )}
            {busy ? "Đang xác thực…" : "Đăng nhập"}
          </button>
        </form>
        <p className="mt-6 border-t border-slate-100 pt-5 text-xs leading-5 text-slate-500">
          Mọi thao tác nhạy cảm đều được ghi nhật ký. Quyền xem dữ liệu gốc tự
          hết hạn sau 60 giây.
        </p>
      </section>
    </main>
  );
}

function AppShell({ onLogout }: { onLogout: () => void }) {
  const [page, setPage] = useState<PageId>("live");
  const [mobileNav, setMobileNav] = useState(false);
  const desktopNav = useMediaQuery("(min-width: 1024px)");
  const currentPage = navItems.find((item) => item.id === page);

  useEffect(() => {
    if (!mobileNav) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileNav(false);
    };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [mobileNav]);

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900">
      {mobileNav && (
        <div
          className="fixed inset-0 z-30 bg-slate-950/25 backdrop-blur-[2px] lg:hidden"
          onClick={() => setMobileNav(false)}
          aria-hidden="true"
        />
      )}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-72 shrink-0 flex-col border-r border-slate-200 bg-white transition-transform duration-200 lg:sticky lg:top-0 lg:h-screen lg:translate-x-0",
          mobileNav ? "translate-x-0" : "-translate-x-full",
        )}
        aria-hidden={!desktopNav && !mobileNav}
        inert={!desktopNav && !mobileNav}
      >
        <div className="flex h-20 items-center gap-3 border-b border-slate-100 px-5">
          <BrandMark small />
          <div>
            <p className="text-sm font-bold tracking-tight text-slate-950">
              Traffic Inspector
            </p>
            <p className="text-xs text-slate-500">Bảng điều khiển quản trị</p>
          </div>
          <button
            className={cn(iconButton, "ml-auto lg:hidden")}
            onClick={() => setMobileNav(false)}
            aria-label="Đóng menu"
          >
            <X size={19} />
          </button>
        </div>
        <nav className="grid gap-1.5 p-4" aria-label="Điều hướng chính">
          <p className="px-3 pb-2 pt-1 text-[11px] font-bold uppercase tracking-[0.14em] text-slate-400">
            Quản lý
          </p>
          {navItems.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={cn(
                "flex min-h-11 w-full items-center gap-3 rounded-xl px-3.5 text-left text-sm font-medium transition focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-emerald-600/15",
                page === id
                  ? "bg-emerald-50 text-emerald-700"
                  : "text-slate-600 hover:bg-slate-50 hover:text-slate-950",
              )}
              onClick={() => {
                setPage(id);
                setMobileNav(false);
              }}
              aria-current={page === id ? "page" : undefined}
            >
              <Icon size={18} />
              {label}
              {page === id && <ChevronRight className="ml-auto" size={16} />}
            </button>
          ))}
        </nav>
        <div className="mt-auto border-t border-slate-100 p-4">
          <div className="mb-2 flex items-center gap-2.5 rounded-xl bg-emerald-50 px-3.5 py-3 text-xs font-medium text-emerald-700">
            <span className="relative flex size-2.5">
              <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-50" />
              <span className="relative inline-flex size-2.5 rounded-full bg-emerald-500" />
            </span>
            Hệ thống thu thập đang hoạt động
          </div>
          <button
            className="flex min-h-11 w-full items-center gap-3 rounded-xl px-3.5 text-sm font-medium text-slate-600 transition hover:bg-rose-50 hover:text-rose-700 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-rose-600/10"
            onClick={onLogout}
          >
            <LogOut size={18} />
            Đăng xuất
          </button>
        </div>
      </aside>
      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-20 flex h-20 items-center justify-between border-b border-slate-200 bg-white/90 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
          <div className="flex min-w-0 items-center gap-3">
            <button
              className={cn(iconButton, "lg:hidden")}
              onClick={() => setMobileNav(true)}
              aria-label="Mở menu"
              aria-expanded={mobileNav}
            >
              <Menu size={21} />
            </button>
            <div className="min-w-0">
              <p className="text-xs text-slate-400">Quản trị</p>
              <p className="truncate text-sm font-semibold text-slate-800">
                {currentPage?.label}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="hidden items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1.5 text-xs font-semibold text-emerald-700 sm:inline-flex">
              <ShieldCheck size={14} />
              Dữ liệu được mã hóa
            </span>
            <button
              className={iconButton}
              onClick={() => window.location.reload()}
              aria-label="Tải lại trang"
              title="Tải lại trang"
            >
              <RefreshCw size={17} />
            </button>
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1700px] p-4 sm:p-6 lg:p-8">
          {page === "live" && <LiveCapture />}
          {page === "sessions" && <Sessions />}
          {page === "devices" && <Devices />}
          {page === "system" && <SystemAudit />}
        </main>
      </div>
    </div>
  );
}

function LiveCapture() {
  const [flows, setFlows] = useState<Flow[]>([]);
  const [selected, setSelected] = useState<string>();
  const [query, setQuery] = useState("");
  const [method, setMethod] = useState("");
  const [status, setStatus] = useState("");
  const [contentType, setContentType] = useState("");
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [paused, setPaused] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (query) params.set("q", query);
      if (method) params.set("method", method);
      if (status) params.set("status_code", status);
      if (contentType) params.set("content_type", contentType);
      const result = await api.flows(params.size ? `?${params}` : "");
      setFlows(result.items);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể tải lưu lượng");
    } finally {
      setLoading(false);
    }
  }, [query, method, status, contentType]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${location.host}/ws/live`);
    socket.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      if (payload.type?.startsWith("flow.")) {
        setFlows((current) => {
          const flow = payload.flow as Flow;
          const index = current.findIndex((item) => item.id === flow.id);
          if (index < 0) return [flow, ...current].slice(0, 500);
          const next = [...current];
          next[index] = { ...next[index], ...flow };
          return next;
        });
      }
    };
    return () => socket.close();
  }, []);

  async function togglePause() {
    try {
      await api.request("/api/system/pause", {
        method: "PUT",
        body: JSON.stringify({ paused: !paused }),
      });
      setPaused(!paused);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Không thể đổi trạng thái thu thập",
      );
    }
  }

  return (
    <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1.35fr)_minmax(390px,.9fr)]">
      <section className={cn(panelClass, "min-w-0 overflow-hidden")}>
        <div className="flex flex-col justify-between gap-5 border-b border-slate-100 p-5 sm:flex-row sm:items-start sm:p-6">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.16em] text-emerald-700">
              Dòng dữ liệu thời gian thực
            </p>
            <h1 className="mt-2 text-2xl font-bold tracking-tight text-slate-950">
              Theo dõi trực tiếp
            </h1>
            <p className="mt-2 text-sm text-slate-500">
              Lưu lượng từ mọi thiết bị đã đăng ký, được lưu đến khi bạn xóa.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              className={cn(
                secondaryButton,
                paused && "border-amber-200 bg-amber-50 text-amber-700",
              )}
              onClick={() => void togglePause()}
            >
              {paused ? <Play size={16} /> : <Pause size={16} />}
              {paused ? "Tiếp tục" : "Tạm dừng ghi"}
            </button>
            <span className="inline-flex h-10 items-center gap-2 rounded-xl bg-emerald-50 px-3 text-xs font-bold text-emerald-700">
              <span className="size-2 rounded-full bg-emerald-500" />
              TRỰC TIẾP
            </span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 bg-slate-50/70 p-3 sm:p-4">
          <label className="flex h-11 min-w-[220px] flex-1 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3.5 text-slate-400 shadow-sm transition focus-within:border-emerald-500 focus-within:ring-4 focus-within:ring-emerald-500/10">
            <Search size={17} />
            <span className="sr-only">Tìm kiếm</span>
            <input
              className="min-w-0 flex-1 bg-transparent text-sm text-slate-900 outline-none placeholder:text-slate-400"
              placeholder="Tìm theo tên miền hoặc đường dẫn…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          <button
            className={cn(
              secondaryButton,
              filtersOpen &&
                "border-emerald-200 bg-emerald-50 text-emerald-700",
            )}
            onClick={() => setFiltersOpen(!filtersOpen)}
            aria-expanded={filtersOpen}
          >
            <Filter size={16} />
            Bộ lọc
          </button>
          <span className="ml-auto hidden text-xs font-medium text-slate-500 sm:block">
            {flows.length} lưu lượng
          </span>
        </div>
        {filtersOpen && (
          <div className="grid gap-2 border-b border-slate-100 bg-slate-50/70 p-3 sm:grid-cols-2 sm:p-4 lg:grid-cols-4">
            <select
              className={inputClass}
              value={method}
              onChange={(event) => setMethod(event.target.value)}
              aria-label="Lọc theo phương thức"
            >
              <option value="">Tất cả phương thức</option>
              <option>GET</option>
              <option>POST</option>
              <option>PUT</option>
              <option>PATCH</option>
              <option>DELETE</option>
            </select>
            <input
              className={inputClass}
              inputMode="numeric"
              placeholder="Mã trạng thái"
              value={status}
              onChange={(event) =>
                setStatus(event.target.value.replace(/\D/g, ""))
              }
            />
            <input
              className={inputClass}
              placeholder="Loại nội dung"
              value={contentType}
              onChange={(event) => setContentType(event.target.value)}
            />
            <button
              className={secondaryButton}
              onClick={() => {
                setMethod("");
                setStatus("");
                setContentType("");
              }}
            >
              <X size={16} />
              Xóa bộ lọc
            </button>
          </div>
        )}
        {error && (
          <div className="p-4 pb-0">
            <InlineError
              message={error}
              actionLabel="Thử lại"
              onAction={() => void refresh()}
            />
          </div>
        )}
        {loading ? (
          <EmptyState
            icon={<RefreshCw className="animate-spin" />}
            title="Đang tải lưu lượng"
            detail="Đang kết nối đến luồng sự kiện được mã hóa…"
          />
        ) : flows.length === 0 ? (
          <EmptyState
            icon={<Wifi />}
            title="Chưa có lưu lượng"
            detail="Hãy kết nối một thiết bị WireGuard đã đăng ký để bắt đầu."
          />
        ) : (
          <div
            className="min-w-0"
            role="table"
            aria-label="Danh sách lưu lượng đã ghi"
          >
            <div
              className="hidden grid-cols-[minmax(190px,1.5fr)_72px_130px_82px_20px] gap-3 border-b border-slate-100 bg-slate-50 px-4 py-2.5 text-[11px] font-bold uppercase tracking-[0.08em] text-slate-400 sm:grid"
              role="row"
            >
              <span>Phương thức / máy chủ</span>
              <span>Trạng thái</span>
              <span>Loại</span>
              <span>Thời gian</span>
              <span />
            </div>
            <div className="max-h-[calc(100vh-330px)] min-h-80 overflow-y-auto">
              {flows.map((flow) => (
                <button
                  className={cn(
                    "grid w-full grid-cols-[minmax(180px,1fr)_64px_18px] items-center gap-3 border-b border-slate-100 px-4 py-3 text-left transition last:border-b-0 hover:bg-emerald-50/60 focus-visible:z-10 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-inset focus-visible:ring-emerald-600/15 sm:grid-cols-[minmax(190px,1.5fr)_72px_130px_82px_20px]",
                    selected === flow.id && "bg-emerald-50",
                  )}
                  key={flow.id}
                  onClick={() => setSelected(flow.id)}
                  role="row"
                >
                  <span className="flex min-w-0 items-center gap-3">
                    <MethodBadge method={flow.method || flow.protocol} />
                    <span className="grid min-w-0 gap-0.5">
                      <strong className="truncate text-sm font-semibold text-slate-800">
                        {flow.host}
                      </strong>
                      <small className="truncate text-xs text-slate-500">
                        {flow.path || "—"}
                      </small>
                    </span>
                  </span>
                  <span
                    className={cn(
                      "text-xs font-bold",
                      stateClasses[flow.state],
                    )}
                  >
                    {flow.state === "loading" ? (
                      <span className="inline-flex items-center gap-1.5">
                        <span className="size-2 animate-pulse rounded-full bg-amber-500" />
                        Chờ
                      </span>
                    ) : (
                      flow.status || "LỖI"
                    )}
                  </span>
                  <span className="hidden truncate text-xs text-slate-500 sm:block">
                    {flow.responseContentType || flow.requestContentType || "—"}
                  </span>
                  <span className="hidden text-xs tabular-nums text-slate-500 sm:block">
                    {formatTime(flow.startedAt)}
                  </span>
                  <ChevronRight size={16} className="text-slate-400" />
                </button>
              ))}
            </div>
          </div>
        )}
      </section>
      {selected ? (
        <FlowDetailPanel
          flowId={selected}
          onClose={() => setSelected(undefined)}
        />
      ) : (
        <section
          className={cn(
            panelClass,
            "grid min-h-[420px] place-items-center px-8 py-14 text-center xl:sticky xl:top-28 xl:min-h-[calc(100vh-144px)]",
          )}
        >
          <div>
            <div className="mx-auto grid size-16 place-items-center rounded-2xl bg-emerald-50 text-emerald-600">
              <Eye size={28} />
            </div>
            <h2 className="mt-5 text-lg font-bold text-slate-900">
              Chọn một lưu lượng
            </h2>
            <p className="mx-auto mt-2 max-w-sm text-sm leading-6 text-slate-500">
              Chọn một dòng bên trái để xem header, nội dung, thời gian và tin
              nhắn WebSocket.
            </p>
          </div>
        </section>
      )}
    </div>
  );
}

function FlowDetailPanel({
  flowId,
  onClose,
}: {
  flowId: string;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<FlowDetail>();
  const [tab, setTab] = useState("request");
  const [error, setError] = useState("");
  const [revealToken, setRevealToken] = useState<string>();
  const [reauthAction, setReauthAction] = useState<ReauthAction>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setDetail(undefined);
    setRevealToken(undefined);
    setError("");
    void api
      .flow(flowId)
      .then(setDetail)
      .catch((err) => setError(err.message));
  }, [flowId]);

  function save(blob: Blob, filename: string) {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  async function exportFlow(raw: boolean, password?: string) {
    setBusy(true);
    setError("");
    try {
      const result = await api.file(
        `/api/flows/${flowId}/export${raw ? "?raw=true" : ""}`,
        {
          method: "POST",
          body: raw ? JSON.stringify({ password }) : undefined,
        },
      );
      save(result.blob, result.filename);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể xuất lưu lượng");
    } finally {
      setBusy(false);
    }
  }

  async function download(
    direction: "request" | "response",
    password?: string,
  ) {
    setBusy(true);
    setError("");
    try {
      let token = revealToken;
      if (!token) {
        const result = await api.request<{ token: string }>(
          `/api/flows/${flowId}/reveal`,
          {
            method: "POST",
            body: JSON.stringify({ password }),
          },
        );
        token = result.token;
        setRevealToken(token);
        window.setTimeout(() => setRevealToken(undefined), 60000);
      }
      const result = await api.file(
        `/api/flows/${flowId}/body/${direction}/download`,
        {
          headers: { "X-Reveal-Token": token },
        },
      );
      save(result.blob, result.filename);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể tải nội dung");
    } finally {
      setBusy(false);
    }
  }

  async function authorize(password: string) {
    if (reauthAction === "raw-export") {
      await exportFlow(true, password);
    } else if (reauthAction?.startsWith("download-")) {
      await download(
        reauthAction.replace("download-", "") as "request" | "response",
        password,
      );
    } else {
      const result = await api.request<{ token: string }>(
        `/api/flows/${flowId}/reveal`,
        {
          method: "POST",
          body: JSON.stringify({ password }),
        },
      );
      setRevealToken(result.token);
      setDetail(await api.flow(flowId, result.token));
      window.setTimeout(() => setRevealToken(undefined), 60000);
    }
    setReauthAction(undefined);
  }

  const tabs = [
    { id: "request", label: "Yêu cầu" },
    { id: "response", label: "Phản hồi" },
    { id: "timing", label: "Thời gian" },
    { id: "websocket", label: "WebSocket" },
  ];

  return (
    <section
      className={cn(
        panelClass,
        "min-w-0 overflow-hidden xl:sticky xl:top-28 xl:min-h-[calc(100vh-144px)]",
      )}
    >
      {reauthAction && (
        <ReauthDialog
          onCancel={() => setReauthAction(undefined)}
          onSubmit={authorize}
        />
      )}
      {!detail ? (
        <EmptyState
          icon={<RefreshCw className="animate-spin" />}
          title="Đang tải chi tiết"
          detail={error || "Đang đọc metadata đã mã hóa…"}
        />
      ) : (
        <>
          <div className="flex items-start justify-between gap-3 border-b border-slate-100 p-5">
            <div className="min-w-0">
              <div className="flex min-w-0 items-center gap-2.5">
                <MethodBadge method={detail.method || detail.protocol} />
                <h2 className="truncate text-lg font-bold text-slate-900">
                  {detail.host}
                </h2>
              </div>
              <p className="mt-2 truncate font-mono text-xs text-slate-500">
                {detail.path || "—"}
              </p>
            </div>
            <button
              className={iconButton}
              onClick={onClose}
              aria-label="Đóng chi tiết"
            >
              <X size={18} />
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-slate-100 px-5 py-3 text-xs text-slate-500">
            <span className={cn("font-bold", stateClasses[detail.state])}>
              {detail.status || detail.state}
            </span>
            <span>
              {detail.durationMs
                ? `${detail.durationMs} ms`
                : "Đang chờ thời gian"}
            </span>
            <span>
              {formatBytes(detail.requestBytes + detail.responseBytes)} đã
              truyền
            </span>
            {detail.raw ? (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-50 px-2.5 py-1 font-semibold text-amber-700">
                <Eye size={13} />
                Đang xem dữ liệu gốc
              </span>
            ) : (
              <button
                className="ml-auto inline-flex items-center gap-1.5 font-semibold text-emerald-700 hover:text-emerald-800"
                onClick={() => setReauthAction("reveal")}
              >
                <Eye size={14} />
                Hiện dữ liệu nhạy cảm
              </button>
            )}
          </div>
          {error && (
            <div className="p-4 pb-0">
              <InlineError message={error} />
            </div>
          )}
          <div className="flex flex-wrap gap-2 border-b border-slate-100 p-3">
            <button
              className={secondaryButton}
              disabled={busy}
              onClick={() => void exportFlow(false)}
            >
              <Download size={15} />
              Xuất dữ liệu
            </button>
            <button
              className={secondaryButton}
              disabled={busy}
              onClick={() => setReauthAction("raw-export")}
            >
              <FileKey2 size={15} />
              Xuất dữ liệu gốc
            </button>
          </div>
          <div
            className="flex gap-1 overflow-x-auto border-b border-slate-200 px-3"
            role="tablist"
          >
            {tabs.map((item) => (
              <button
                role="tab"
                aria-selected={tab === item.id}
                className={cn(
                  "whitespace-nowrap border-b-2 px-3 py-3 text-sm font-semibold transition focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-emerald-600/15",
                  tab === item.id
                    ? "border-emerald-600 text-emerald-700"
                    : "border-transparent text-slate-500 hover:text-slate-800",
                )}
                key={item.id}
                onClick={() => setTab(item.id)}
              >
                {item.label}
              </button>
            ))}
          </div>
          {tab === "request" && (
            <MessageView
              direction="request"
              detail={detail}
              token={revealToken}
              onDownload={() => setReauthAction("download-request")}
            />
          )}
          {tab === "response" && (
            <MessageView
              direction="response"
              detail={detail}
              token={revealToken}
              onDownload={() => setReauthAction("download-response")}
            />
          )}
          {tab === "timing" && <TimingView detail={detail} />}
          {tab === "websocket" && (
            <WebSocketView flowId={flowId} token={revealToken} />
          )}
        </>
      )}
    </section>
  );
}

function MessageView({
  direction,
  detail,
  token,
  onDownload,
}: {
  direction: "request" | "response";
  detail: FlowDetail;
  token?: string;
  onDownload: () => void;
}) {
  const [body, setBody] = useState<BodyPreview>();

  useEffect(() => {
    setBody(undefined);
    void api
      .body(detail.id, direction, token)
      .then(setBody)
      .catch(() =>
        setBody({
          state: "error",
          encoding: "",
          content: "",
          view: "text",
          raw: false,
          truncated: false,
        }),
      );
  }, [detail.id, direction, token]);

  const headers =
    direction === "request" ? detail.requestHeaders : detail.responseHeaders;
  const bodyBytes =
    direction === "request" ? detail.requestBytes : detail.responseBytes;

  return (
    <div className="grid gap-5 p-4 sm:p-5">
      <div className="rounded-xl border border-slate-200 bg-slate-50 px-3">
        <InfoLine label="URL" value={detail.url} mono />
        <InfoLine
          label="Tham số"
          value={
            detail.query.length
              ? detail.query.map(([key, value]) => `${key}=${value}`).join("&")
              : "Không có"
          }
          mono
        />
      </div>
      <section>
        <SectionHeading title="Header" meta={`${headers.length} mục`} />
        <HeadersTable headers={headers} />
      </section>
      <section>
        <SectionHeading
          title="Nội dung"
          meta={
            body?.truncated
              ? "Bản xem trước đã bị rút gọn"
              : formatBytes(bodyBytes)
          }
          action={
            <button
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700 hover:text-emerald-800"
              onClick={onDownload}
            >
              <Download size={14} />
              Tải bản đầy đủ
            </button>
          }
        />
        {body ? (
          <BodyBox body={body} />
        ) : (
          <div className="grid min-h-32 place-items-center rounded-xl border border-slate-200 bg-slate-50 text-sm text-slate-500">
            <span className="inline-flex items-center gap-2">
              <RefreshCw className="animate-spin" size={16} />
              Đang tải nội dung…
            </span>
          </div>
        )}
      </section>
    </div>
  );
}

function SectionHeading({
  title,
  meta,
  action,
}: {
  title: string;
  meta?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="mb-2.5 flex items-center gap-2">
      <h3 className="text-sm font-bold text-slate-800">{title}</h3>
      {meta && <span className="text-xs text-slate-400">{meta}</span>}
      {action && <span className="ml-auto">{action}</span>}
    </div>
  );
}

function HeadersTable({ headers }: { headers: string[][] }) {
  if (!headers.length) {
    return (
      <div className="rounded-xl border border-dashed border-slate-200 p-5 text-center text-sm text-slate-500">
        Không có header.
      </div>
    );
  }
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200">
      {headers.map(([key, value], index) => (
        <div
          className="grid grid-cols-[minmax(100px,.7fr)_minmax(0,1.4fr)] gap-3 border-b border-slate-100 px-3 py-2.5 text-xs last:border-b-0"
          key={`${key}-${index}`}
        >
          <span className="truncate font-medium text-slate-500">{key}</span>
          <code className="truncate font-mono text-slate-700" title={value}>
            {value}
          </code>
        </div>
      ))}
    </div>
  );
}

function InfoLine({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="grid grid-cols-[75px_minmax(0,1fr)] gap-3 border-b border-slate-200 py-2.5 text-xs last:border-b-0">
      <span className="font-medium text-slate-500">{label}</span>
      <code
        className={cn("truncate text-slate-700", mono && "font-mono")}
        title={value}
      >
        {value}
      </code>
    </div>
  );
}

function BodyBox({ body }: { body: BodyPreview }) {
  const [showRaw, setShowRaw] = useState(false);
  let text = "";
  try {
    text = atob(body.content);
    if (body.view === "json" && !showRaw)
      text = JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    text = "Nội dung nhị phân";
  }

  return (
    <div className="max-h-96 overflow-auto rounded-xl border border-slate-200 bg-slate-950">
      <div className="sticky top-0 flex items-center gap-2 border-b border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-300">
        <span className="rounded-md bg-slate-700 px-2 py-1 font-mono text-[11px] text-slate-200">
          {body.view}
        </span>
        {body.raw && (
          <button
            className="ml-auto inline-flex items-center gap-1.5 font-semibold text-emerald-300 hover:text-emerald-200"
            onClick={() => setShowRaw(!showRaw)}
          >
            {showRaw ? <EyeOff size={14} /> : <Eye size={14} />}
            {showRaw ? "Ẩn dữ liệu gốc" : "Hiện dữ liệu gốc"}
          </button>
        )}
        {body.state === "truncated" && (
          <span className="ml-auto text-amber-300">
            Bản xem trước bị giới hạn
          </span>
        )}
      </div>
      {body.state === "not-captured" ? (
        <p className="p-5 text-sm text-slate-400">
          Nội dung không được lưu cho lưu lượng này.
        </p>
      ) : body.state === "error" ? (
        <p className="p-5 text-sm text-rose-300">
          Không thể giải mã nội dung từ bộ nhớ.
        </p>
      ) : (
        <pre className="whitespace-pre-wrap break-words p-4 font-mono text-xs leading-6 text-slate-200">
          {text}
        </pre>
      )}
    </div>
  );
}

function TimingView({ detail }: { detail: FlowDetail }) {
  return (
    <div className="grid gap-7 p-5">
      <div className="flex items-center gap-4 rounded-2xl border border-emerald-100 bg-emerald-50 p-4 text-emerald-700">
        <span className="grid size-10 place-items-center rounded-xl bg-white shadow-sm">
          <Clock3 size={19} />
        </span>
        <div>
          <span className="text-xs font-medium">Tổng thời gian</span>
          <strong className="block text-xl text-emerald-900">
            {detail.durationMs ? `${detail.durationMs} ms` : "Đang chờ"}
          </strong>
        </div>
      </div>
      <div className="grid gap-5">
        <TimelineRow label="Thiết bị → proxy" width="12%" value="2 ms" />
        <TimelineRow
          label="Proxy → máy chủ"
          width="52%"
          value={
            detail.durationMs
              ? `${Math.max(1, Math.floor(detail.durationMs * 0.52))} ms`
              : "—"
          }
        />
        <TimelineRow
          label="Máy chủ → proxy"
          width="36%"
          value={
            detail.durationMs
              ? `${Math.max(1, Math.floor(detail.durationMs * 0.36))} ms`
              : "—"
          }
        />
      </div>
    </div>
  );
}

function TimelineRow({
  label,
  width,
  value,
}: {
  label: string;
  width: string;
  value: string;
}) {
  return (
    <div className="grid grid-cols-[105px_minmax(0,1fr)_52px] items-center gap-3 text-xs">
      <span className="text-slate-500">{label}</span>
      <span className="h-2 overflow-hidden rounded-full bg-slate-100">
        <i
          className="block h-full rounded-full bg-gradient-to-r from-emerald-500 to-green-400"
          style={{ width }}
        />
      </span>
      <b className="text-right font-semibold tabular-nums text-slate-700">
        {value}
      </b>
    </div>
  );
}

function WebSocketView({ flowId, token }: { flowId: string; token?: string }) {
  const [messages, setMessages] = useState<WebSocketMessage[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    void api
      .websocket(flowId, token)
      .then((result) => {
        setMessages(result.items);
        setError("");
      })
      .catch((err) => setError(err.message));
  }, [flowId, token]);

  if (error) {
    return (
      <EmptyState
        icon={<AlertCircle />}
        title="Không thể tải WebSocket"
        detail={error}
        compact
      />
    );
  }
  if (!messages.length) {
    return (
      <EmptyState
        icon={<Terminal />}
        title="Chưa có tin nhắn WebSocket"
        detail="Lưu lượng này không có tin nhắn WebSocket đã được lưu."
        compact
      />
    );
  }
  return (
    <div className="grid gap-4 p-4 sm:p-5">
      {messages.map((message) => (
        <div
          className="overflow-hidden rounded-xl border border-slate-200"
          key={message.id}
        >
          <div className="flex flex-wrap items-center gap-2 bg-slate-50 px-3 py-2 text-xs text-slate-500">
            <span className="rounded-full bg-emerald-100 px-2.5 py-1 font-semibold text-emerald-700">
              {message.fromClient ? "Thiết bị → máy chủ" : "Máy chủ → thiết bị"}
            </span>
            <span className="ml-auto">
              opcode {message.opcode} · {formatBytes(message.payloadSize)} ·{" "}
              {formatTime(message.timestamp)}
            </span>
          </div>
          <BodyBox body={message.payload} />
        </div>
      ))}
    </div>
  );
}

function ReauthDialog({
  onCancel,
  onSubmit,
}: {
  onCancel: () => void;
  onSubmit: (password: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onSubmit(password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể xác thực");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-slate-950/35 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="reauth-title"
    >
      <form
        className="relative w-full max-w-md rounded-3xl border border-slate-200 bg-white p-7 shadow-2xl shadow-slate-950/15"
        onSubmit={submit}
      >
        <button
          type="button"
          className={cn(iconButton, "absolute right-4 top-4")}
          onClick={onCancel}
          aria-label="Đóng"
        >
          <X size={18} />
        </button>
        <span className="grid size-11 place-items-center rounded-2xl bg-amber-50 text-amber-700">
          <Eye size={20} />
        </span>
        <h2 id="reauth-title" className="mt-5 text-xl font-bold text-slate-950">
          Xem dữ liệu nhạy cảm?
        </h2>
        <p className="mt-2 text-sm leading-6 text-slate-500">
          Thao tác này được ghi nhật ký và quyền xem tạm thời sẽ hết hạn sau 60
          giây.
        </p>
        <label className={cn(labelClass, "mt-6")}>
          Xác nhận mật khẩu quản trị
          <input
            className={inputClass}
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
            autoFocus
          />
        </label>
        {error && (
          <div className="mt-4">
            <InlineError message={error} />
          </div>
        )}
        <div className="mt-6 flex justify-end gap-2">
          <button type="button" className={secondaryButton} onClick={onCancel}>
            Hủy
          </button>
          <button className={primaryButton} disabled={busy}>
            {busy && <RefreshCw className="animate-spin" size={16} />}
            {busy ? "Đang xác thực…" : "Cho phép trong 60 giây"}
          </button>
        </div>
      </form>
    </div>
  );
}

function Sessions() {
  const [rows, setRows] = useState<Session[]>([]);
  const [error, setError] = useState("");
  const refresh = useCallback(() => {
    void api
      .sessions()
      .then((result) => {
        setRows(result);
        setError("");
      })
      .catch((err) => setError(err.message));
  }, []);

  useEffect(refresh, [refresh]);

  async function remove(id: string) {
    if (
      !window.confirm(
        "Xóa phiên này cùng các tệp nội dung đã mã hóa? Thao tác này không thể hoàn tác.",
      )
    ) {
      return;
    }
    try {
      await api.deleteSession(id);
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể xóa phiên");
    }
  }

  return (
    <Page
      title="Phiên đã lưu"
      eyebrow="Kho lưu trữ"
      detail="Xem lại các phiên đã giữ và chủ động quản lý dung lượng."
    >
      {error && <InlineError message={error} />}
      <section className={cn(panelClass, "overflow-hidden")}>
        <div className="flex items-center justify-between gap-4 border-b border-slate-100 p-5 sm:p-6">
          <div>
            <h2 className="font-bold text-slate-900">Danh sách phiên</h2>
            <p className="mt-1 text-sm text-slate-500">
              {rows.length} phiên đang được lưu
            </p>
          </div>
          <button className={secondaryButton} onClick={refresh}>
            <RefreshCw size={16} />
            Làm mới
          </button>
        </div>
        {rows.length ? (
          <div className="overflow-x-auto">
            <div className="min-w-[720px]">
              <div className="grid grid-cols-[minmax(190px,1.6fr)_1.1fr_.5fr_.8fr_44px] items-center gap-4 bg-slate-50 px-5 py-3 text-[11px] font-bold uppercase tracking-[0.08em] text-slate-400">
                <span>Phiên</span>
                <span>Bắt đầu</span>
                <span>Lưu lượng</span>
                <span>Dung lượng nội dung</span>
                <span />
              </div>
              {rows.map((row) => (
                <div
                  className="grid grid-cols-[minmax(190px,1.6fr)_1.1fr_.5fr_.8fr_44px] items-center gap-4 border-t border-slate-100 px-5 py-4 text-sm text-slate-600"
                  key={row.id}
                >
                  <span className="grid gap-1">
                    <strong className="font-semibold text-slate-800">
                      {row.name}
                    </strong>
                    <small className="font-mono text-xs text-slate-400">
                      {row.id.slice(0, 12)}…
                    </small>
                  </span>
                  <span>{formatDate(row.startedAt)}</span>
                  <span>{row.flowCount}</span>
                  <span>{formatBytes(row.bytes)}</span>
                  <button
                    className={cn(
                      iconButton,
                      "text-rose-600 hover:bg-rose-50 hover:text-rose-700",
                    )}
                    aria-label={`Xóa phiên ${row.name}`}
                    onClick={() => void remove(row.id)}
                  >
                    <Trash2 size={17} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <EmptyState
            icon={<Archive />}
            title="Chưa có phiên nào"
            detail="Phiên sẽ xuất hiện khi thiết bị đã đăng ký bắt đầu kết nối."
          />
        )}
      </section>
    </Page>
  );
}

function Devices() {
  const [rows, setRows] = useState<Device[]>([]);
  const [error, setError] = useState("");
  const [deviceName, setDeviceName] = useState("Điện thoại của tôi");
  const [profile, setProfile] = useState<DeviceProfile>();
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(() => {
    void api
      .devices()
      .then((result) => {
        setRows(result);
        setError("");
      })
      .catch((err) => setError(err.message));
  }, []);

  useEffect(refresh, [refresh]);

  function downloadProfile() {
    if (!profile) return;
    const blob = new Blob([profile.profile], {
      type: "text/plain;charset=utf-8",
    });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = profile.filename || "device.conf";
    link.click();
    URL.revokeObjectURL(link.href);
  }

  async function generateProfile() {
    setBusy(true);
    setError("");
    try {
      const result = await api.createDeviceProfile(deviceName);
      setProfile(result);
      refresh();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Không thể tạo cấu hình WireGuard",
      );
    } finally {
      setBusy(false);
    }
  }

  async function copyPublicKey() {
    if (!profile) return;
    await navigator.clipboard?.writeText(profile.peerPublicKey);
  }

  async function revoke(id: string, name: string) {
    if (
      !window.confirm(
        `Thu hồi quyền của ${name}? Việc chuyển tiếp lưu lượng sẽ dừng sau lần đồng bộ tiếp theo.`,
      )
    ) {
      return;
    }
    try {
      await api.revokeDevice(id);
      refresh();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Không thể thu hồi thiết bị",
      );
    }
  }

  return (
    <Page
      title="Thiết bị & cài đặt"
      eyebrow="Thiết bị được phép"
      detail="Tạo cấu hình WireGuard, kết nối điện thoại và quản lý quyền truy cập."
    >
      {error && <InlineError message={error} />}
      <div className="grid items-start gap-5 xl:grid-cols-2">
        <section className={cn(panelClass, "p-5 sm:p-6")}>
          <span className="grid size-11 place-items-center rounded-2xl bg-emerald-50 text-emerald-700">
            <FileKey2 size={20} />
          </span>
          <h2 className="mt-5 text-lg font-bold text-slate-900">
            Kết nối thiết bị mới
          </h2>
          <p className="mt-2 text-sm leading-6 text-slate-500">
            Tạo cấu hình WireGuard ngay trong trình duyệt, sau đó quét mã QR
            hoặc tải tệp .conf.
          </p>
          <div className="mt-6 grid gap-3">
            <label className={labelClass}>
              Tên thiết bị
              <input
                className={inputClass}
                value={deviceName}
                onChange={(event) => setDeviceName(event.target.value)}
                maxLength={128}
              />
            </label>
            <button
              className={primaryButton}
              disabled={busy || !deviceName.trim()}
              onClick={() => void generateProfile()}
            >
              {busy ? (
                <RefreshCw className="animate-spin" size={16} />
              ) : (
                <FileKey2 size={16} />
              )}
              {busy ? "Đang tạo cấu hình…" : "Tạo cấu hình"}
            </button>
          </div>
          {profile ? (
            <div className="mt-6 grid gap-4">
              <div className="grid place-items-center gap-3 rounded-2xl border border-emerald-100 bg-emerald-50 p-5 text-center">
                <div className="rounded-2xl bg-white p-3 shadow-sm">
                  <QRCodeSVG value={profile.profile} size={192} level="M" />
                </div>
                <div>
                  <p className="text-sm font-bold text-emerald-900">
                    Quét bằng ứng dụng WireGuard
                  </p>
                  <p className="mt-1 text-xs text-emerald-700">
                    Hoặc tải tệp cấu hình ở bên dưới.
                  </p>
                </div>
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                <button className={secondaryButton} onClick={downloadProfile}>
                  <Download size={15} />
                  Tải tệp .conf
                </button>
                <button
                  className={secondaryButton}
                  onClick={() => void copyPublicKey()}
                >
                  <Copy size={15} />
                  Sao chép public key
                </button>
              </div>
              <div className="rounded-xl border border-slate-200 bg-slate-50 px-3">
                <InfoLine label="Peer key" value={profile.peerPublicKey} mono />
                <InfoLine
                  label="IP tunnel"
                  value={profile.tunnelIp || "Đang chờ"}
                  mono
                />
              </div>
            </div>
          ) : (
            <ol className="mt-6 grid gap-4">
              {[
                "Bấm “Tạo cấu hình” sau khi dịch vụ thu thập đã chạy.",
                "Quét mã QR trong WireGuard hoặc tải tệp cấu hình.",
                "Cài chứng chỉ CA công khai rồi bật tin cậy cho ứng dụng cần kiểm tra.",
              ].map((step, index) => (
                <li
                  className="flex gap-3 text-sm leading-6 text-slate-600"
                  key={step}
                >
                  <span className="grid size-7 shrink-0 place-items-center rounded-full bg-slate-100 text-xs font-bold text-slate-500">
                    {index + 1}
                  </span>
                  {index === 2 ? (
                    <span>
                      Cài{" "}
                      <a
                        className="font-semibold text-emerald-700 underline decoration-emerald-300 underline-offset-4"
                        href="/setup/mitmproxy-ca-cert.pem"
                      >
                        chứng chỉ CA công khai
                      </a>{" "}
                      rồi bật tin cậy cho ứng dụng cần kiểm tra.
                    </span>
                  ) : (
                    <span>{step}</span>
                  )}
                </li>
              ))}
            </ol>
          )}
          <div className="mt-6 flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 p-3.5 text-xs leading-5 text-amber-800">
            <ShieldCheck className="mt-0.5 shrink-0" size={17} />
            Cấu hình chứa private key. Chỉ hiển thị hoặc tải xuống trên thiết bị
            quản trị đáng tin cậy.
          </div>
        </section>
        <section className={cn(panelClass, "overflow-hidden")}>
          <div className="flex items-center gap-3 border-b border-slate-100 p-5 sm:p-6">
            <span className="grid size-11 place-items-center rounded-2xl bg-green-50 text-green-700">
              <Smartphone size={20} />
            </span>
            <div>
              <h2 className="font-bold text-slate-900">Thiết bị đã đăng ký</h2>
              <p className="mt-1 text-sm text-slate-500">
                {rows.length} thiết bị
              </p>
            </div>
            <button
              className={cn(iconButton, "ml-auto")}
              onClick={refresh}
              aria-label="Làm mới danh sách thiết bị"
            >
              <RefreshCw size={17} />
            </button>
          </div>
          {rows.length ? (
            <div>
              {rows.map((row) => (
                <div
                  className="flex items-center gap-3 border-b border-slate-100 px-5 py-4 last:border-b-0"
                  key={row.id}
                >
                  <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-slate-100 text-slate-600">
                    <Smartphone size={17} />
                  </span>
                  <div className="min-w-0 flex-1">
                    <strong className="block truncate text-sm font-semibold text-slate-800">
                      {row.name}
                    </strong>
                    <small className="mt-0.5 block truncate text-xs text-slate-500">
                      {row.tunnelIp || "Đang chờ địa chỉ tunnel"}
                    </small>
                  </div>
                  <span
                    className={cn(
                      "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold",
                      row.revokedAt
                        ? "bg-rose-50 text-rose-700"
                        : "bg-emerald-50 text-emerald-700",
                    )}
                  >
                    <span
                      className={cn(
                        "size-1.5 rounded-full",
                        row.revokedAt ? "bg-rose-500" : "bg-emerald-500",
                      )}
                    />
                    {row.revokedAt ? "Đã thu hồi" : "Đang hoạt động"}
                  </span>
                  {!row.revokedAt && (
                    <button
                      className={cn(
                        iconButton,
                        "text-rose-600 hover:bg-rose-50 hover:text-rose-700",
                      )}
                      aria-label={`Thu hồi ${row.name}`}
                      onClick={() => void revoke(row.id, row.name)}
                    >
                      <Trash2 size={17} />
                    </button>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<Laptop />}
              title="Chưa có thiết bị"
              detail="Hãy tạo cấu hình ở bên cạnh để thêm thiết bị đầu tiên."
            />
          )}
        </section>
      </div>
    </Page>
  );
}

function SystemAudit() {
  const [system, setSystem] = useState<SystemOverview>();
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [error, setError] = useState("");

  const refresh = useCallback(() => {
    void Promise.all([api.system(), api.audit()])
      .then(([systemResult, auditResult]) => {
        setSystem(systemResult);
        setAudit(auditResult);
        setError("");
      })
      .catch((err) =>
        setError(err instanceof Error ? err.message : "Không thể tải hệ thống"),
      );
  }, []);

  useEffect(refresh, [refresh]);

  const metrics = [
    {
      icon: Database,
      label: "Nội dung đã ghi",
      value: formatBytes(system?.recordedBodyBytes || 0),
    },
    {
      icon: Server,
      label: "Dung lượng trống",
      value: formatBytes(system?.disk?.free || 0),
    },
    {
      icon: Activity,
      label: "Sự kiện đang chờ",
      value: system?.spooledEvents || 0,
    },
    {
      icon: AlertCircle,
      label: "Sự kiện bị bỏ",
      value: system?.droppedEvents || 0,
    },
  ];

  return (
    <Page
      title="Hệ thống & nhật ký"
      eyebrow="Vận hành"
      detail="Theo dõi dung lượng, sức khỏe ingest và các thao tác nhạy cảm."
    >
      {error && (
        <InlineError message={error} actionLabel="Thử lại" onAction={refresh} />
      )}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {metrics.map(({ icon: Icon, label, value }) => (
          <div className={cn(panelClass, "p-5")} key={label}>
            <span className="grid size-10 place-items-center rounded-xl bg-emerald-50 text-emerald-700">
              <Icon size={18} />
            </span>
            <span className="mt-4 block text-sm text-slate-500">{label}</span>
            <strong className="mt-1 block text-xl font-bold tracking-tight text-slate-900">
              {value}
            </strong>
          </div>
        ))}
      </div>
      <section className={cn(panelClass, "overflow-hidden")}>
        <div className="flex items-center justify-between gap-4 border-b border-slate-100 p-5 sm:p-6">
          <div>
            <h2 className="font-bold text-slate-900">Nhật ký thao tác</h2>
            <p className="mt-1 text-sm text-slate-500">
              Ghi lại thao tác xem dữ liệu gốc, xuất dữ liệu và quản lý thiết
              bị.
            </p>
          </div>
          <button className={secondaryButton} onClick={refresh}>
            <RefreshCw size={16} />
            Làm mới
          </button>
        </div>
        {audit.length ? (
          <div className="overflow-x-auto">
            <div className="min-w-[720px]">
              <div className="grid grid-cols-[1.5fr_1fr_1fr_1fr] gap-4 bg-slate-50 px-5 py-3 text-[11px] font-bold uppercase tracking-[0.08em] text-slate-400">
                <span>Thao tác</span>
                <span>Đối tượng</span>
                <span>Nguồn</span>
                <span>Thời gian</span>
              </div>
              {audit.map((row) => (
                <div
                  className="grid grid-cols-[1.5fr_1fr_1fr_1fr] gap-4 border-t border-slate-100 px-5 py-4 text-sm text-slate-600"
                  key={row.id}
                >
                  <strong className="font-semibold text-slate-800">
                    {row.action}
                  </strong>
                  <span>
                    {row.targetType
                      ? `${row.targetType} ${row.targetId?.slice(0, 10) || ""}`
                      : "—"}
                  </span>
                  <span>{row.sourceIp || "—"}</span>
                  <span>{formatDate(row.createdAt)}</span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <EmptyState
            icon={<CheckCircle2 />}
            title="Nhật ký đang trống"
            detail="Các thao tác nhạy cảm sẽ xuất hiện tại đây."
          />
        )}
      </section>
    </Page>
  );
}

function Page({
  title,
  eyebrow,
  detail,
  children,
}: {
  title: string;
  eyebrow: string;
  detail: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-5">
      <div className="mb-1">
        <p className="text-xs font-bold uppercase tracking-[0.16em] text-emerald-700">
          {eyebrow}
        </p>
        <h1 className="mt-2 text-2xl font-bold tracking-tight text-slate-950 sm:text-3xl">
          {title}
        </h1>
        <p className="mt-2 text-sm leading-6 text-slate-500">{detail}</p>
      </div>
      {children}
    </div>
  );
}

function MethodBadge({ method }: { method: string }) {
  return (
    <span
      className={cn(
        "inline-flex min-w-12 shrink-0 justify-center rounded-lg px-2 py-1 text-[10px] font-extrabold tracking-wide ring-1 ring-inset",
        methodClasses[method] ||
          "bg-slate-100 text-slate-600 ring-slate-500/20",
      )}
    >
      {method}
    </span>
  );
}

function InlineError({
  message,
  actionLabel,
  onAction,
}: {
  message: string;
  actionLabel?: string;
  onAction?: () => void;
}) {
  return (
    <div
      className="flex items-start gap-2.5 rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700"
      role="alert"
    >
      <AlertCircle className="mt-0.5 shrink-0" size={17} />
      <span className="min-w-0 flex-1">{message}</span>
      {actionLabel && onAction && (
        <button
          className="font-semibold underline underline-offset-4"
          onClick={onAction}
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}

function EmptyState({
  icon,
  title,
  detail,
  compact = false,
}: {
  icon: React.ReactNode;
  title: string;
  detail: string;
  compact?: boolean;
}) {
  return (
    <div
      className={cn(
        "grid place-items-center text-center",
        compact ? "p-8" : "p-12 sm:p-16",
      )}
    >
      <div className="grid size-12 place-items-center rounded-2xl bg-emerald-50 text-emerald-600">
        {icon}
      </div>
      <h2 className="mt-4 font-bold text-slate-900">{title}</h2>
      <p className="mt-1.5 max-w-sm text-sm leading-6 text-slate-500">
        {detail}
      </p>
    </div>
  );
}

function Root() {
  const [authenticated, setAuthenticated] = useState<boolean | undefined>();

  useEffect(() => {
    const handler = () => setAuthenticated(false);
    window.addEventListener("mti:unauthenticated", handler);
    void api
      .request("/auth/me")
      .then(() => setAuthenticated(true))
      .catch(() => setAuthenticated(false));
    return () => window.removeEventListener("mti:unauthenticated", handler);
  }, []);

  if (authenticated === undefined) {
    return (
      <div className="grid min-h-screen place-items-center bg-slate-50 text-sm text-slate-500">
        <span className="inline-flex items-center gap-3">
          <ShieldCheck className="animate-pulse text-emerald-600" size={24} />
          Đang mở khu vực quản trị…
        </span>
      </div>
    );
  }

  return authenticated ? (
    <AppShell
      onLogout={() => {
        void api
          .request("/auth/logout", { method: "POST" })
          .finally(() => setAuthenticated(false));
      }}
    />
  ) : (
    <Login onLogin={() => setAuthenticated(true)} />
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Root />
  </StrictMode>,
);
