import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

// Gate for the protected pages: show them only if someone is logged in,
// otherwise redirect to the login page.
export default function ProtectedRoute() {
  const { user } = useAuth();
  return user ? <Outlet /> : <Navigate to="/login" replace />;
}
