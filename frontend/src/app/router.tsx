import { createBrowserRouter } from "react-router-dom";
import { AppShell } from "@/layouts/AppShell";
import { LandingPage } from "@/pages/LandingPage";
import { DashboardPage } from "@/pages/DashboardPage";
import { EventsPage } from "@/pages/EventsPage";
import { EventDetailPage } from "@/pages/EventDetailPage";
import { AlertsPage } from "@/pages/AlertsPage";
import { AlertDetailPage } from "@/pages/AlertDetailPage";
import { IncidentsPage } from "@/pages/IncidentsPage";
import { InjectPage } from "@/pages/InjectPage";
import { IncidentDetailPage } from "@/pages/IncidentDetailPage";
import { InvestigationPage } from "@/pages/InvestigationPage";
import { ThreatLabPage } from "@/pages/ThreatLabPage";
import { NotFoundPage } from "@/pages/NotFoundPage";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <LandingPage />,
  },
  {
    element: <AppShell />,
    children: [
      { path: "/dashboard", element: <DashboardPage /> },
      { path: "/events", element: <EventsPage /> },
      { path: "/events/:id", element: <EventDetailPage /> },
      { path: "/alerts", element: <AlertsPage /> },
      { path: "/alerts/:id", element: <AlertDetailPage /> },
      { path: "/incidents", element: <IncidentsPage /> },
      { path: "/inject", element: <InjectPage /> },
      { path: "/threat-lab", element: <ThreatLabPage /> },
      { path: "/incidents/:id", element: <IncidentDetailPage /> },
      { path: "/incidents/:id/investigation", element: <InvestigationPage /> },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
]);
