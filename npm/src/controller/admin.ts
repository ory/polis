import {
  IAdminController,
  Storable,
  SAMLSSORecord,
  OIDCSSORecord,
  SSOTracesInstance,
  Records,
  Trace,
} from '../typings';
import { JacksonError } from './error';
import { transformConnections } from './utils';

export class AdminController implements IAdminController {
  private connectionStore: Storable;
  private ssoTraces: SSOTracesInstance;

  constructor({ connectionStore, ssoTraces }) {
    this.connectionStore = connectionStore;
    this.ssoTraces = ssoTraces;
  }

  public async getAllConnection(pageOffset?: number, pageLimit?: number, pageToken?: string) {
    const { data: connectionList, pageToken: nextPageToken } = (await this.connectionStore.getAll(
      pageOffset,
      pageLimit,
      pageToken
    )) as Records<SAMLSSORecord | OIDCSSORecord>;

    if (!connectionList || !connectionList.length) {
      return { data: [] };
    }

    return { data: transformConnections(connectionList), pageToken: nextPageToken };
  }

  public async getAllSSOTraces(pageOffset: number, pageLimit: number, pageToken?: string) {
    const { data: traces, pageToken: nextPageToken } = (await this.ssoTraces.getAllTraces(
      pageOffset,
      pageLimit,
      pageToken
    )) as Records<Trace>;

    if (!traces || !traces.length) {
      return { data: [] };
    }

    return { data: traces, pageToken: nextPageToken };
  }

  public async getSSOTraceById(traceId: string) {
    const trace = await this.ssoTraces.getByTraceId(traceId);

    if (!trace) {
      throw new JacksonError(`Trace with id ${traceId} not found`, 404);
    }

    return trace;
  }

  public async getTracesByProduct(
    product: string,
    pageOffset: number,
    pageLimit: number,
    pageToken?: string
  ) {
    return await this.ssoTraces.getTracesByProduct({ product, pageOffset, pageLimit, pageToken });
  }

  public async deleteTracesByProduct(product: string) {
    return await this.ssoTraces.deleteTracesByProduct(product);
  }

  public async countByProduct(product: string) {
    return await this.ssoTraces.countByProduct(product);
  }
}
