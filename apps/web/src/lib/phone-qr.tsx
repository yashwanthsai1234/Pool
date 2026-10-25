// "Scan to register" for the laptop screens: phones cannot open localhost, so the server reports the laptop's LAN
// address and this shows it as a QR code (the same SVG QR as the ZKPassport request).
import { useQuery } from '@tanstack/react-query';
import { QrCode } from '../zk/ui.tsx';
import { API_BASE } from './paths.ts';
import { PHONE_BASE_URL } from './phone-url.gen.ts';

const isLocal = () => ['localhost', '127.0.0.1'].includes(location.hostname);

export function PhoneSignupQr() {
  const lan = useQuery({
    queryKey: ['demo', 'phone-urls'],
    enabled: isLocal(),
    queryFn: async (): Promise<string[]> => {
      const r = await fetch(`${API_BASE}/demo/phone-urls`);
      if (!r.ok) throw new Error(`phone-urls ${r.status}`);
      return ((await r.json()) as { urls: string[] }).urls;
    },
  });
  const url = PHONE_BASE_URL ? `${PHONE_BASE_URL}/register` : isLocal() ? lan.data?.[0] : `${location.origin}/register`;
  return (
    <section className="flex flex-col items-center gap-3 rounded-xl border p-5 text-center">
      <h2 className="text-xl font-bold">Phones: scan to register</h2>
      <p className="text-muted">Alice and Bob each scan this on their own phone and enter their name.</p>
      {url ? (
        <>
          <QrCode value={url} />
          <code className="break-all text-sm">{url}</code>
        </>
      ) : (
        <p className="text-muted">
          {lan.isError ? 'Could not find the laptop’s Wi-Fi address.' : 'Finding the laptop’s address…'}
        </p>
      )}
    </section>
  );
}
