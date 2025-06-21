import { useTranslation } from 'next-i18next';
import { useState } from 'react';
import XMarkIcon from '@heroicons/react/24/outline/XMarkIcon';
import ChevronDownIcon from '@heroicons/react/24/outline/ChevronDownIcon';
import type { AttributeMapping } from '../types';

const standardAttributes = {
  saml: [
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
    'http://schemas.xmlsoap.org/claims/Group',
  ],
  oidc: ['sub', 'email', 'given_name', 'family_name', 'roles', 'groups'],
};

export const AttributesMapping = ({
  mappings,
  onAttributeMappingsChange,
}: {
  mappings: AttributeMapping[];
  onAttributeMappingsChange: (attributeMappings: AttributeMapping[]) => void;
}) => {
  const { t } = useTranslation('common');

  const addAnother = () => {
    onAttributeMappingsChange([...mappings, { key: '', value: '' }]);
  };

  return (
    <div className='space-y-6'>
      {mappings.length > 0 && (
        <div className='grid grid-cols-12 gap-4 items-center pb-2 border-b border-gray-200'>
          <div className='col-span-5'>
            <label className='block text-sm font-semibold text-gray-700'>{t('bui-fs-sp-attribute')}</label>
          </div>
          <div className='col-span-6'>
            <label className='block text-sm font-semibold text-gray-700'>{t('bui-fs-idp-attribute')}</label>
          </div>
          <div className='col-span-1'></div>
        </div>
      )}

      <div className='space-y-4'>
        {mappings.map((attributeMapping, index) => (
          <AttributeRow
            key={index}
            attributeMapping={attributeMapping}
            onMappingChange={(newAttributeMapping) => {
              const newMappings = [...mappings];
              newMappings[index] = newAttributeMapping;
              onAttributeMappingsChange(newMappings);
            }}
            onMappingDelete={() => {
              onAttributeMappingsChange(mappings.filter((_, i) => i !== index));
            }}
          />
        ))}

        <div className='pt-4'>
          <button
            className='btn btn-primary btn-sm btn-outline hover:btn-primary transition-colors duration-200'
            type='button'
            onClick={addAnother}>
            {mappings.length === 0 ? t('bui-fs-add-mapping') : t('bui-fs-add-another')}
          </button>
        </div>
      </div>
    </div>
  );
};

const AttributeRow = ({
  attributeMapping,
  onMappingChange,
  onMappingDelete,
}: {
  attributeMapping: AttributeMapping;
  onMappingChange: (newAttributeMapping: AttributeMapping) => void;
  onMappingDelete: () => void;
}) => {
  const { t } = useTranslation('common');
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);

  const handleAttributeSelect = (value: string) => {
    onMappingChange({
      key: attributeMapping.key,
      value: value,
    });
    setIsDropdownOpen(false);
  };

  const toggleDropdown = () => {
    setIsDropdownOpen(!isDropdownOpen);
  };

  return (
    <div className='grid grid-cols-12 gap-4 items-center transition-colors duration-200'>
      {/* SP Attribute Input */}
      <div className='col-span-5'>
        <input
          type='text'
          className='input input-bordered input-sm w-full focus:ring-2 focus:ring-gray-400 focus:border-gray-400'
          placeholder='Enter attribute name'
          name='attribute'
          value={attributeMapping.key}
          onChange={(e) => {
            onMappingChange({
              key: e.target.value,
              value: attributeMapping.value,
            });
          }}
          required
        />
      </div>

      {/* IDP Attribute Input with Dropdown */}
      <div className='col-span-6 relative'>
        <div className='flex'>
          <input
            type='text'
            className='input input-bordered input-sm w-full rounded-r-none focus:ring-2 focus:ring-gray-400 focus:border-gray-400 z-10'
            placeholder='Enter or select attribute'
            name='mapping'
            value={attributeMapping.value}
            onChange={(e) => {
              onMappingChange({
                key: attributeMapping.key,
                value: e.target.value,
              });
            }}
            required
          />
          <button
            type='button'
            className='flex items-center justify-center h-8 w-8 border border-gray-300 rounded-r-md border-l-0 hover:bg-gray-100 focus:ring-2 focus:ring-gray-400 focus:outline-none bg-white'
            onClick={toggleDropdown}
            aria-label='Show attribute options'>
            <ChevronDownIcon
              className={`h-4 w-4 transition-transform duration-200 ${isDropdownOpen ? 'rotate-180' : ''}`}
            />
          </button>
        </div>

        {/* Dropdown Menu */}
        {isDropdownOpen && (
          <>
            {/* Backdrop */}
            <div className='fixed inset-0 z-10' onClick={() => setIsDropdownOpen(false)}></div>

            {/* Dropdown Content */}
            <div className='absolute top-full left-0 right-0 mt-1 bg-white border border-gray-300 rounded-md shadow-lg z-20 max-h-64 overflow-y-auto'>
              <div className='py-1'>
                <div className='px-3 py-2 text-xs font-semibold text-gray-500 uppercase tracking-wide bg-gray-100 border-b'>
                  {t('bui-fs-saml-attributes')}
                </div>
                {standardAttributes.saml.map((attribute) => (
                  <button
                    key={attribute}
                    type='button'
                    className='w-full text-left px-3 py-2 text-sm hover:bg-gray-100 hover:text-gray-800 focus:bg-gray-100 focus:text-gray-800 focus:outline-none transition-colors duration-150'
                    onClick={() => handleAttributeSelect(attribute)}>
                    <div className='truncate' title={attribute}>
                      {attribute}
                    </div>
                  </button>
                ))}

                <div className='px-3 py-2 text-xs font-semibold text-gray-500 uppercase tracking-wide bg-gray-100 border-b border-t'>
                  {t('bui-fs-oidc-attributes')}
                </div>
                {standardAttributes.oidc.map((attribute) => (
                  <button
                    key={attribute}
                    type='button'
                    className='w-full text-left px-3 py-2 text-sm hover:bg-gray-100 hover:text-gray-800 focus:bg-gray-100 focus:text-gray-800 focus:outline-none transition-colors duration-150'
                    onClick={() => handleAttributeSelect(attribute)}>
                    <div className='truncate' title={attribute}>
                      {attribute}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </>
        )}
      </div>

      {/* Delete Button */}
      <div className='col-span-1 flex justify-center'>
        <button
          type='button'
          onClick={onMappingDelete}
          className='p-1 rounded-full hover:bg-red-100 focus:ring-2 focus:ring-gray-400 focus:outline-none transition-colors duration-200'
          aria-label='Delete mapping'>
          <XMarkIcon className='h-5 w-5 text-red-500 hover:text-red-700' />
        </button>
      </div>
    </div>
  );
};
