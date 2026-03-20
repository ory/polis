import { JSX } from 'react';
import { Button } from 'rsc-daisyui';
import { useTranslation } from 'next-i18next';
import { Badge } from './Badge';

const tableWrapperClass = 'rounder border';
const tableClass = 'w-full text-left text-sm text-gray-500 dark:text-gray-400';
const trClass = 'border-b bg-white last:border-b-0 hover:bg-gray-50 dark:border-gray-700 dark:bg-gray-800';
const tdClassBase = 'px-6 py-2 text-sm text-gray-500 dark:text-gray-400';
const tdClass = `whitespace-nowrap ${tdClassBase}`;
const tdClassWrap = `break-all ${tdClassBase}`;
const theadClass = 'bg-gray-50 text-xs uppercase text-gray-700 dark:bg-gray-700 dark:text-gray-400';
const trHeadClass = 'hover:bg-gray-50';
const thClass = 'px-6 py-3';

export interface TableBodyCell {
  wrap?: boolean;
  text?: string;
  buttons?: {
    text: string;
    color?: string;
    onClick: () => void;
  }[];
  badge?: {
    text: string;
    color: string;
  };
  element?: JSX.Element;
  actions?: {
    text: string;
    icon: JSX.Element;
    onClick: () => void;
    destructive?: boolean;
  }[];
}

export interface TableBodyType {
  id: string;
  cells: TableBodyCell[];
}

const TableBody = ({
  cols,
  body,
  noMoreResults,
}: {
  cols: string[];
  body: TableBodyType[];
  noMoreResults?: boolean;
}) => {
  const { t } = useTranslation('common');

  if (noMoreResults) {
    return (
      <tbody>
        <tr>
          <td colSpan={cols.length} className='px-6 py-2 text-center text-sm text-gray-500'>
            {t('bui-shared-no-more-results')}
          </td>
        </tr>
      </tbody>
    );
  }

  return (
    <tbody>
      {body.map((row) => {
        return (
          <tr key={row.id} className={trClass}>
            {row.cells?.map((cell: any, index: number) => {
              return (
                <td key={row.id + '-td-' + index} className={cell.wrap ? tdClassWrap : tdClass}>
                  {!cell.buttons || cell.buttons?.length === 0 ? null : (
                    <div className='flex space-x-2'>
                      {cell.buttons?.map((button: any, index: number) => {
                        return (
                          <Button
                            key={row.id + '-button-' + index}
                            size='xs'
                            color={button.color}
                            outline={true}
                            onClick={button.onClick}>
                            {button.text}
                          </Button>
                        );
                      })}
                    </div>
                  )}
                  {!cell.actions || cell.actions?.length === 0 ? null : (
                    <span className='flex gap-3'>
                      {cell.actions?.map((action: any, index: number) => {
                        return (
                          <div key={row.id + '-diva-' + index} className='tooltip' data-tip={action.text}>
                            <button
                              key={row.id + '-action-' + index}
                              className={`py-2 ${
                                action.destructive
                                  ? 'text-red-500 hover:text-red-900'
                                  : 'hover:text-green-400'
                              }`}
                              onClick={action.onClick}>
                              {action.icon}
                            </button>
                          </div>
                        );
                      })}
                    </span>
                  )}
                  {cell.badge ? <Badge color={cell.badge.color}>{cell.badge.text}</Badge> : null}
                  {cell.text ? cell.text : null}
                  {cell.element ? cell.element : null}
                </td>
              );
            })}
          </tr>
        );
      })}
    </tbody>
  );
};

const TableHeader = ({ cols }: { cols: string[] }) => {
  return (
    <thead className={theadClass}>
      <tr className={trHeadClass}>
        {cols.map((col, index) => (
          <th key={index} scope='col' className={thClass}>
            {col}
          </th>
        ))}
      </tr>
    </thead>
  );
};

export const Table = ({
  cols,
  body,
  noMoreResults,
}: {
  cols: string[];
  body: TableBodyType[];
  noMoreResults?: boolean;
}) => {
  return (
    <div className={tableWrapperClass}>
      <table className={tableClass}>
        <TableHeader cols={cols} />
        <TableBody cols={cols} body={body} noMoreResults={noMoreResults} />
      </table>
    </div>
  );
};
