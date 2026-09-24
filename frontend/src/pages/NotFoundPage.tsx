import { Link } from "react-router-dom";
import { Button } from "@/components/ui/Button";

export function NotFoundPage() {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <h1 className="text-2xl font-semibold text-slate-100">Page not found</h1>
      <p className="mt-2 text-sm text-slate-400">The page you requested does not exist.</p>
      <Link to="/dashboard" className="mt-6">
        <Button variant="outline">Go to Dashboard</Button>
      </Link>
    </div>
  );
}
