//! OAuth helpers for AT Protocol.
//!
//! `primitives` contains PKCE, DPoP, client assertions, and form/JWKS helpers.
//! `client` contains framework-neutral ATProto OAuth client ceremony.

const primitives = @import("oauth/primitives.zig");
const client = @import("oauth/client.zig");

pub const createJwt = primitives.createJwt;
pub const createDpopProof = primitives.createDpopProof;
pub const createClientAssertion = primitives.createClientAssertion;
pub const generatePkceVerifier = primitives.generatePkceVerifier;
pub const generatePkceChallenge = primitives.generatePkceChallenge;
pub const generateState = primitives.generateState;
pub const accessTokenHash = primitives.accessTokenHash;
pub const formEncode = primitives.formEncode;
pub const jwksJson = primitives.jwksJson;

pub const AuthorizationServerMetadata = client.AuthorizationServerMetadata;
pub const AuthRequestSecrets = client.AuthRequestSecrets;
pub const ClientMetadataParams = client.ClientMetadataParams;
pub const ParParams = client.ParParams;
pub const ParResult = client.ParResult;
pub const CodeTokenParams = client.CodeTokenParams;
pub const RefreshTokenParams = client.RefreshTokenParams;
pub const TokenResult = client.TokenResult;
pub const DpopRequest = client.DpopRequest;
pub const DpopResponse = client.DpopResponse;

pub const prepareAuthRequestSecrets = client.prepareAuthRequestSecrets;
pub const parseTokenResponse = client.parseTokenResponse;
pub const clientMetadataJson = client.clientMetadataJson;
pub const authorizationUrl = client.authorizationUrl;
pub const discoverAuthorizationServer = client.discoverAuthorizationServer;
pub const fetchAuthorizationServerMetadata = client.fetchAuthorizationServerMetadata;
pub const parseAuthorizationServerMetadata = client.parseAuthorizationServerMetadata;
pub const sendParRequest = client.sendParRequest;
pub const exchangeCodeForToken = client.exchangeCodeForToken;
pub const refreshAccessToken = client.refreshAccessToken;
pub const dpopRequest = client.dpopRequest;
pub const isDpopNonceChallenge = client.isDpopNonceChallenge;
