import axios from 'axios';
import type { RequiredLogger } from '../typings';

const retry = 3;
const retryDelay = 3000;

export const createAxiosInstance = (logger: RequiredLogger) => {
  const axiosInstance = axios.create({
    maxContentLength: 1000000,
    maxBodyLength: 1000000,
    timeout: 20000,
  });

  // Axios interceptors to handle the Webhook retries
  axiosInstance.interceptors.response.use(undefined, (err: any) => {
    const config = err.config;

    if (!config) {
      return Promise.reject(err);
    }

    config.__retryCount = config.__retryCount || 0;

    if (config.__retryCount >= retry) {
      return Promise.reject(err);
    }

    config.__retryCount += 1;

    const backoff = new Promise(function (resolve) {
      setTimeout(function () {
        resolve(1);
      }, retryDelay);
    });

    return backoff.then(function () {
      logger.info(`Retrying sending webhook event to ${config.url}... Attempt ${config.__retryCount}`);
      return axiosInstance(config);
    });
  });

  return axiosInstance;
};
