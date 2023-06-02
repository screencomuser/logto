import { assert } from '@silverhand/essentials';

import type {
  GetAuthorizationUri,
  GetUserInfo,
  GetConnectorConfig,
  CreateConnector,
  SocialConnector,
} from '@logto/connector-kit';
import {
  ConnectorError,
  ConnectorErrorCodes,
  validateConfig,
  ConnectorType,
  connectorDataParser,
} from '@logto/connector-kit';
import { generateStandardId } from '@logto/shared/universal';
import { createRemoteJWKSet, jwtVerify } from 'jose';

import { scope, defaultMetadata, jwksUri, issuer, authorizationEndpoint } from './constant.js';
import type { AppleConfig, AuthorizationData } from './types.js';
import { appleConfigGuard, authorizationDataGuard } from './types.js';

const generateNonce = () => generateStandardId();

const getAuthorizationUri =
  (getConfig: GetConnectorConfig): GetAuthorizationUri =>
  async ({ state, redirectUri }, setSession) => {
    const config = await getConfig(defaultMetadata.id);

    validateConfig<AppleConfig>(config, appleConfigGuard);

    const nonce = generateNonce();

    const queryParameters = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: redirectUri,
      scope,
      state,
      nonce,
      // https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/incorporating_sign_in_with_apple_into_other_platforms#3332113
      response_type: 'code id_token',
      response_mode: 'fragment',
    });

    assert(
      setSession,
      new ConnectorError(ConnectorErrorCodes.NotImplemented, {
        message: "'setSession' is not implemented.",
      })
    );
    await setSession({ nonce });

    return `${authorizationEndpoint}?${queryParameters.toString()}`;
  };

const getUserInfo =
  (getConfig: GetConnectorConfig): GetUserInfo =>
  async (data, getSession) => {
    const { id_token: idToken } = connectorDataParser<AuthorizationData>(
      data,
      authorizationDataGuard,
      ConnectorErrorCodes.General
    );

    if (!idToken) {
      throw new ConnectorError(ConnectorErrorCodes.SocialIdTokenInvalid, {
        message: 'IdToken is not presented.',
      });
    }

    const config = await getConfig(defaultMetadata.id);
    validateConfig<AppleConfig>(config, appleConfigGuard);

    const { clientId } = config;

    try {
      const { payload } = await jwtVerify(idToken, createRemoteJWKSet(new URL(jwksUri)), {
        issuer,
        audience: clientId,
      });

      if (payload.nonce) {
        // TODO @darcy: need to specify error code
        assert(
          getSession,
          new ConnectorError(ConnectorErrorCodes.NotImplemented, {
            message: "'getSession' is not implemented.",
            data: payload,
          })
        );
        const { nonce: validationNonce } = await getSession();

        assert(
          validationNonce,
          new ConnectorError(ConnectorErrorCodes.General, {
            message: "'nonce' not presented in session storage.",
            data: payload,
          })
        );

        assert(
          validationNonce === payload.nonce,
          new ConnectorError(ConnectorErrorCodes.SocialIdTokenInvalid, {
            message: "IdToken validation failed due to 'nonce' mismatch.",
            data: payload,
          })
        );
      }

      if (!payload.sub) {
        throw new ConnectorError(ConnectorErrorCodes.SocialIdTokenInvalid, {
          message: "IdToken validation failed due to 'sub' not presented",
          data: payload,
        });
      }

      return {
        id: payload.sub,
      };
    } catch {
      throw new ConnectorError(ConnectorErrorCodes.SocialIdTokenInvalid, { data: idToken });
    }
  };

const createAppleConnector: CreateConnector<SocialConnector> = async ({ getConfig }) => {
  return {
    metadata: defaultMetadata,
    type: ConnectorType.Social,
    configGuard: appleConfigGuard,
    getAuthorizationUri: getAuthorizationUri(getConfig),
    getUserInfo: getUserInfo(getConfig),
  };
};

export default createAppleConnector;
