import { Loading } from '@boxyhq/internal-ui';
import type { NextPage } from 'next';
import { useRouter } from 'next/router';
import { useEffect } from 'react';

const Home: NextPage = () => {
  const router = useRouter();

  useEffect(() => {
    router.push('/admin/sso-connection');
  }, [router]);

  return (
    <div style={{ margin: '10px' }}>
      <Loading />
    </div>
  );
};

export default Home;
