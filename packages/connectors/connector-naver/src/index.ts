/**
 * The Implementation of OAuth2 of Naver.
 * https://developers.naver.com/docs/login/api/api.md
 */
import { assert, conditional } from '@silverhand/essentials';
import { got, HTTPError } from 'got';

import type {
  CreateConnector,
  GetAuthorizationUri,
  GetConnectorConfig,
  GetUserInfo,
  SocialConnector,
} from '@logto/connector-kit';
import {
  ConnectorError,
  ConnectorErrorCodes,
  ConnectorType,
  validateConfig,
  parseJson,
  connectorDataParser,
} from '@logto/connector-kit';

import {
  accessTokenEndpoint,
  authorizationEndpoint,
  defaultMetadata,
  defaultTimeout,
  userInfoEndpoint,
} from './constant.js';
import type { NaverConfig, AccessTokenResponse, UserInfoResponse, AuthResponse } from './types.js';
import {
  accessTokenResponseGuard,
  authResponseGuard,
  naverConfigGuard,
  userInfoResponseGuard,
} from './types.js';

const getAuthorizationUri =
  (getConfig: GetConnectorConfig): GetAuthorizationUri =>
  async ({ state, redirectUri }) => {
    const config = await getConfig(defaultMetadata.id);
    validateConfig<NaverConfig>(config, naverConfigGuard);

    const queryParameters = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      state,
    });

    return `${authorizationEndpoint}?${queryParameters.toString()}`;
  };

export const getAccessToken = async (
  config: NaverConfig,
  codeObject: { code: string; redirectUri: string }
) => {
  const { code, redirectUri } = codeObject;
  const { clientId, clientSecret } = config;

  // Note：Need to decodeURIComponent on code
  // https://stackoverflow.com/questions/51058256/google-api-node-js-invalid-grant-malformed-auth-code
  const httpResponse = await got.post(accessTokenEndpoint, {
    form: {
      code: decodeURIComponent(code),
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    },
    timeout: { request: defaultTimeout },
  });

  const parsedBody = parseJson(httpResponse.body);
  const { access_token: accessToken } = connectorDataParser<AccessTokenResponse>(
    parsedBody,
    accessTokenResponseGuard
  );

  assert(
    accessToken,
    new ConnectorError(ConnectorErrorCodes.SocialAuthCodeInvalid, {
      data: accessToken,
      message: 'accessToken is empty',
    })
  );

  return { accessToken };
};

const getUserInfo =
  (getConfig: GetConnectorConfig): GetUserInfo =>
  async (data) => {
    const { code, redirectUri } = connectorDataParser<AuthResponse>(
      data,
      authResponseGuard,
      ConnectorErrorCodes.General
    );
    const config = await getConfig(defaultMetadata.id);
    validateConfig<NaverConfig>(config, naverConfigGuard);
    const { accessToken } = await getAccessToken(config, { code, redirectUri });

    try {
      const httpResponse = await got.post(userInfoEndpoint, {
        headers: {
          authorization: `Bearer ${accessToken}`,
        },
        timeout: { request: defaultTimeout },
      });

      const parsedBody = parseJson(httpResponse.body);
      const { response } = connectorDataParser<UserInfoResponse>(parsedBody, userInfoResponseGuard);
      const { id, email, nickname, profile_image } = response;

      return {
        id,
        avatar: conditional(profile_image),
        email: conditional(email),
        name: conditional(nickname),
      };
    } catch (error: unknown) {
      return getUserInfoErrorHandler(error);
    }
  };

const getUserInfoErrorHandler = (error: unknown) => {
  if (error instanceof HTTPError) {
    const { statusCode } = error.response;

    throw new ConnectorError(
      statusCode === 401
        ? ConnectorErrorCodes.SocialAccessTokenInvalid
        : ConnectorErrorCodes.General,
      { data: error.response }
    );
  }

  throw error;
};

const createNaverConnector: CreateConnector<SocialConnector> = async ({ getConfig }) => {
  return {
    metadata: defaultMetadata,
    type: ConnectorType.Social,
    configGuard: naverConfigGuard,
    getAuthorizationUri: getAuthorizationUri(getConfig),
    getUserInfo: getUserInfo(getConfig),
  };
};

export default createNaverConnector;
