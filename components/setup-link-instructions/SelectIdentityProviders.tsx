import { useRouter } from 'next/router';

import { identityProviders } from '@lib/constants';

const SelectIdentityProviders = () => {
  const router = useRouter();

  const onClick = (id: string) => {
    const params = new URLSearchParams({
      idp: id,
      step: '1',
    });

    router.push(router.asPath + '?' + params.toString());
  };

  return (
    <div className='grid gap-4 grid-cols-2 w-full'>
      {identityProviders.map((provider) => (
        <button
          key={provider.id}
          className='text-left border p-4 rounded hover:border-primary font-bold'
          onClick={() => onClick(provider.id)}>
          {provider.name}
        </button>
      ))}
    </div>
  );
};

export default SelectIdentityProviders;
