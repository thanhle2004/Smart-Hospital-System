"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { authService } from "@/features/auth/services/auth.service";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Input } from "@/components/ui/input";
import {
  BedDouble,
  Clock3,
  FolderKanban,
  LayoutDashboard,
  LogOut,
  RefreshCw,
  ShieldCheck,
  Stethoscope,
  UserRound,
  Users,
  Workflow,
  Layers,
  HeartPulse,
  CheckCircle2,
} from "lucide-react";
import type { MeResponse } from "@/features/auth/types/auth.type";

type MenuItem = {
  title: string;
  path: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
};

type AdminStats = {
  users: number;
  rooms: number;
  roomTypes: number;
  flows: number;
  patientTypes: number;
  priorityRules: number;
  patients: number;
  totalVisitsToday: number;
  ongoingVisits: number;
  completedVisitsToday: number;
};

type RoomLiveInfo = {
  id: number;
  name: string;
  roomNumber: number;
  roomTypeName: string;
  activeDoctors: number;
  waitingPatients: number;
  capacity: number;
};

type AdminDashboardResponse = {
  stats: AdminStats;
  rooms: RoomLiveInfo[];
};

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5000";

const menu: MenuItem[] = [
  {
    title: "Patient Types",
    path: "/admin/patient-types",
    description: "Manage patient type catalog and baseline priorities",
    icon: UserRound,
  },
  {
    title: "Patients",
    path: "/admin/patients",
    description: "Manage patient records and profile information",
    icon: HeartPulse,
  },
  {
    title: "Rooms",
    path: "/admin/rooms",
    description: "Manage clinic rooms, capacities, and configurations",
    icon: BedDouble,
  },
  {
    title: "Room Types",
    path: "/admin/room-types",
    description: "Define room type templates used across flows",
    icon: Layers,
  },
  {
    title: "Appointment Flows",
    path: "/admin/flows",
    description: "Design and update treatment workflow templates",
    icon: Workflow,
  },
  {
    title: "Priority Rules",
    path: "/admin/priority",
    description: "Configure queue prioritization logic and conditions",
    icon: Clock3,
  },
  {
    title: "Users",
    path: "/admin/users",
    description: "Manage system users and role-based access",
    icon: Users,
  },
];

const initialStats: AdminStats = {
  users: 0,
  rooms: 0,
  roomTypes: 0,
  flows: 0,
  patientTypes: 0,
  priorityRules: 0,
  patients: 0,
  totalVisitsToday: 0,
  ongoingVisits: 0,
  completedVisitsToday: 0,
};

const statCards = [
  {
    key: "users" as const,
    label: "System users",
    icon: Users,
    colorClass: "text-blue-600",
    bgClass: "bg-blue-50",
  },
  {
    key: "rooms" as const,
    label: "Clinic rooms",
    icon: BedDouble,
    colorClass: "text-emerald-600",
    bgClass: "bg-emerald-50",
  },
  {
    key: "roomTypes" as const,
    label: "Room types",
    icon: Layers,
    colorClass: "text-cyan-600",
    bgClass: "bg-cyan-50",
  },
  {
    key: "flows" as const,
    label: "Flow templates",
    icon: Workflow,
    colorClass: "text-violet-600",
    bgClass: "bg-violet-50",
  },
  {
    key: "patientTypes" as const,
    label: "Patient types",
    icon: FolderKanban,
    colorClass: "text-indigo-600",
    bgClass: "bg-indigo-50",
  },
  {
    key: "priorityRules" as const,
    label: "Priority rules",
    icon: Clock3,
    colorClass: "text-amber-600",
    bgClass: "bg-amber-50",
  },
  {
    key: "patients" as const,
    label: "Registered patients",
    icon: UserRound,
    colorClass: "text-pink-600",
    bgClass: "bg-pink-50",
  },
  {
    key: "totalVisitsToday" as const,
    label: "Visits today",
    icon: HeartPulse,
    colorClass: "text-rose-600",
    bgClass: "bg-rose-50",
  },
  {
    key: "ongoingVisits" as const,
    label: "Currently treating",
    icon: Stethoscope,
    colorClass: "text-orange-600",
    bgClass: "bg-orange-50",
  },
  {
    key: "completedVisitsToday" as const,
    label: "Completed today",
    icon: CheckCircle2,
    colorClass: "text-emerald-700",
    bgClass: "bg-emerald-50",
  },
];

async function fetchDashboardData(): Promise<AdminDashboardResponse> {
  const res = await fetch(`${API_BASE}/room/admin-dashboard`, {
    credentials: "include",
  });

  if (!res.ok) {
    throw new Error("Failed to fetch admin dashboard data");
  }

  return res.json();
}

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<MeResponse | null>(null);
  const [stats, setStats] = useState<AdminStats>(initialStats);
  const [roomList, setRoomList] = useState<RoomLiveInfo[]>([]);
  const [roomSearch, setRoomSearch] = useState("");
  const [roomTypeFilter, setRoomTypeFilter] = useState("");
  const [minDoctors, setMinDoctors] = useState("");
  const [maxDoctors, setMaxDoctors] = useState("");
  const [minWaiting, setMinWaiting] = useState("");
  const [maxWaiting, setMaxWaiting] = useState("");
  const [minCapacity, setMinCapacity] = useState("");
  const [maxCapacity, setMaxCapacity] = useState("");
  const [loadingStats, setLoadingStats] = useState(true);
  const [statsError, setStatsError] = useState<string | null>(null);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);

  const filteredRoomList = useMemo(() => {
    const search = roomSearch.trim().toLowerCase();
    const typeSearch = roomTypeFilter.trim().toLowerCase();

    return roomList.filter((room) => {
      const matchSearch =
        search.length === 0 ||
        room.name.toLowerCase().includes(search) ||
        String(room.roomNumber).includes(search);

      const matchType =
        typeSearch.length === 0 || room.roomTypeName.toLowerCase().includes(typeSearch);

      return matchSearch && matchType;
    });
  }, [
    roomList,
    roomSearch,
    roomTypeFilter,
    minDoctors,
    maxDoctors,
    minWaiting,
    maxWaiting,
    minCapacity,
    maxCapacity,
  ]);

  const resetRoomFilters = () => {
    setRoomSearch("");
    setRoomTypeFilter("");
  };

  const today = useMemo(
    () =>
      new Date().toLocaleDateString("en-US", {
        weekday: "long",
        day: "numeric",
        month: "long",
        year: "numeric",
      }),
    [],
  );

  const loadStats = async () => {
    setLoadingStats(true);
    setStatsError(null);

    try {
      const dashboard = await fetchDashboardData();
      setStats(dashboard.stats);
      setRoomList(dashboard.rooms);
    } catch {
      setStatsError("Unable to load dashboard statistics.");
    } finally {
      setLoadingStats(false);
    }
  };

  useEffect(() => {
    authService
      .me()
      .then(setUser)
      .catch(() => router.push("/login"));

    loadStats();
  }, [router]);

  const handleLogout = async () => {
    setIsLoggingOut(true);
    setLogoutError(null);

    try {
      await authService.logout();
      router.push("/login");
    } catch {
      setLogoutError("Failed to log out, please try again.");
    } finally {
      setIsLoggingOut(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 flex">
      <aside className="w-64 bg-white border-r flex flex-col flex-shrink-0 sticky top-0 h-screen">
        <div className="p-5 border-b">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-10 rounded-lg bg-primary flex items-center justify-center">
              <ShieldCheck className="w-4 h-4 text-primary-foreground" />
            </div>
            <span className="font-bold text-sm">Admin Console</span>
          </div>
        </div>

        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          <div className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-black text-white font-medium text-sm">
            <LayoutDashboard className="w-4 h-4" />
            Dashboard
          </div>
          {menu.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.path}
                onClick={() => router.push(item.path)}
                title={item.description}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-muted-foreground hover:bg-black/50 hover:text-white hover:shadow-sm active:scale-[0.98] transition-all duration-150 text-sm"
              >
                <Icon className="w-4 h-4" />
                {item.title}
              </button>
            );
          })}
        </nav>

        <div className="p-3 border-t">
          <div className="flex items-center gap-2.5 mb-2 px-2">
            <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
              <span className="text-xs font-bold text-primary">
                {(user?.profile?.fullName ?? user?.email ?? "A")
                  .split(" ")
                  .pop()
                  ?.[0]
                  ?.toUpperCase()}
              </span>
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium truncate">
                {user?.profile?.fullName ?? user?.email}
              </p>
              <p className="text-[11px] text-muted-foreground">Admin</p>
            </div>
          </div>

          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="w-full justify-start text-muted-foreground text-xs h-8 hover:bg-black hover:text-white"
            onClick={handleLogout}
            disabled={isLoggingOut}
          >
            <LogOut className="w-3.5 h-3.5 mr-2" />
            {isLoggingOut ? "Logging out..." : "Logout"}
          </Button>

          {logoutError && (
            <p className="text-xs text-red-600 mt-2 px-2">{logoutError}</p>
          )}
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="bg-white border-b px-8 py-4 flex items-center justify-between flex-shrink-0 sticky top-0 z-10">
          <div>
            <h1 className="text-xl font-bold">Admin Dashboard</h1>
            <p className="text-xs text-muted-foreground capitalize mt-0.5">{today}</p>
          </div>

          <Button variant="outline" size="sm" onClick={loadStats} disabled={loadingStats} className="hover:bg-black hover:text-white">
            <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${loadingStats ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </header>

        <main className="flex-1 p-8 space-y-8 overflow-auto">
          <section>
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-4">
              Today’s Overview
            </h2>
            <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
              {statCards.map(({ key, label, icon: Icon, colorClass, bgClass }) => (
                <Card key={key} className="hover:shadow-md transition-shadow py-0">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-sm text-muted-foreground font-medium">
                        {label}
                      </span>
                      <div className={`p-2 rounded-lg ${bgClass}`}>
                        <Icon className={`w-4 h-4 ${colorClass}`} />
                      </div>
                    </div>
                    <p className="text-3xl font-bold tracking-tight">
                      {loadingStats ? "..." : stats[key]}
                    </p>
                  </CardContent>
                </Card>
              ))}
            </div>
            {statsError && <p className="text-sm text-red-600 mt-3">{statsError}</p>}
          </section>

          <Separator />

          <section>
            <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-widest mb-4">
              Room Activity
            </h2>
            <Card className="py-0">
              <CardContent className="p-0">
                <div className="border-b px-4 py-4 bg-muted/10">
                  <div className="flex items-center justify-between mb-3 gap-3">
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      Advanced Filters
                    </p>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="hover:bg-black hover:text-white"
                      onClick={resetRoomFilters}
                    >
                      Reset Filters
                    </Button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-2 gap-3">
                    <Input
                      placeholder="Search room name / number"
                      value={roomSearch}
                      onChange={(e) => setRoomSearch(e.target.value)}
                    />
                    <Input
                      placeholder="Filter by room type"
                      value={roomTypeFilter}
                      onChange={(e) => setRoomTypeFilter(e.target.value)}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-12 border-b bg-muted/30 px-4 py-3 text-xs font-semibold text-muted-foreground">
                  <div className="col-span-3">Room</div>
                  <div className="col-span-3">Room Type</div>
                  <div className="col-span-2 text-center">Doctors</div>
                  <div className="col-span-2 text-center">Waiting</div>
                  <div className="col-span-2 text-center">Capacity</div>
                </div>

                {filteredRoomList.length === 0 ? (
                  <div className="px-4 py-8 text-sm text-muted-foreground text-center">
                    No matching room activity data.
                  </div>
                ) : (
                  filteredRoomList.map((room) => (
                    <div
                      key={room.id}
                      className="grid grid-cols-12 items-center px-4 py-3 border-b last:border-b-0 text-sm"
                    >
                      <div className="col-span-3 font-medium">
                        {room.name} (#{room.roomNumber})
                      </div>
                      <div className="col-span-3 text-muted-foreground">{room.roomTypeName}</div>
                      <div className="col-span-2 text-center font-semibold">{room.activeDoctors}</div>
                      <div className="col-span-2 text-center font-semibold">{room.waitingPatients}</div>
                      <div className="col-span-2 text-center font-semibold">{room.capacity}</div>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          </section>
        </main>
      </div>
    </div>
  );
}