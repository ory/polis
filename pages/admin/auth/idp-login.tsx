import { useEffect } from 'react';
import { useRouter } from 'next/router';
import { signIn } from 'next-auth/react';

export default function Page() {
  const router = useRouter();

  const { isReady, query } = router;

  useEffect(() => {
    if (!isReady) return;

    signIn('boxyhq-saml-idplogin', {
      code: query?.code,
      callbackUrl: '/',
    });
  }, [isReady, query?.code]);

  return null;
}
