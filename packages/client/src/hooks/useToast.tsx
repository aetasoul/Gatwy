import { useEffect, useState } from 'react';

type ToastType = 'success' | 'error';
interface ToastMsg { id: number; type: ToastType; text: string; }

let counter = 0;
const listeners = new Set<(toast: ToastMsg) => void>();

/** Fire-and-forget momentary toast; call from anywhere, no provider needed. */
export function showToast(text: string, type: ToastType = 'success') {
  const toast: ToastMsg = { id: ++counter, type, text };
  listeners.forEach((fn) => fn(toast));
}

/** Mounted once near the root of a surface to render toasts fired via showToast(). */
export function ToastHost() {
  const [toasts, setToasts] = useState<ToastMsg[]>([]);

  useEffect(() => {
    const onToast = (toast: ToastMsg) => {
      setToasts((prev) => [...prev, toast]);
      setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== toast.id)), 3000);
    };
    listeners.add(onToast);
    return () => { listeners.delete(onToast); };
  }, []);

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-6 right-6 z-[200] flex flex-col gap-2 items-end pointer-events-none">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`px-4 py-2.5 rounded-lg shadow-2xl text-sm font-medium text-white ${
            t.type === 'success' ? 'bg-green-600' : 'bg-red-600'
          }`}
        >
          {t.text}
        </div>
      ))}
    </div>
  );
}
