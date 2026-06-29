import { Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import AppLayout from "./components/AppLayout";
import Dashboard from "./pages/Dashboard";
import ActiveAlerts from "./pages/ActiveAlerts";
import Tenants from "./pages/Tenants";
import TenantDetail from "./pages/TenantDetail";
import EventDetail from "./pages/EventDetail";
import Login from "./pages/Login";

// Sets up all the pages and their URLs. The login page is open to everyone;
// every other page sits behind ProtectedRoute, so a signed-out user is sent to
// login, and inside the shared AppLayout (sidebar, header, search).
function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<AppLayout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<ActiveAlerts />} />
            <Route path="/tenants" element={<Tenants />} />
            <Route path="/tenants/:group" element={<TenantDetail />} />
            <Route path="/alerts/:id" element={<EventDetail />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Route>
      </Routes>
    </AuthProvider>
  );
}

export default App;
