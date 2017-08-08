module Doorkeeper
  module AccessTokenMixin
    extend ActiveSupport::Concern

    include OAuth::Helpers
    include Models::Expirable
    include Models::Revocable
    include Models::Accessible
    include Models::Scopes
    include ActiveModel::MassAssignmentSecurity if defined?(::ProtectedAttributes)

    module ClassMethods
      # Returns an instance of the Doorkeeper::AccessToken with
      # specific token value.
      #
      # @param token [#to_s]
      #   token value (any object that responds to `#to_s`)
      #
      # @return [Doorkeeper::AccessToken, nil] AccessToken object or nil
      #   if there is no record with such token
      #

      def decode(jwt)
        secret_key = Doorkeeper::JWT.configuration.secret_key
        algorithm = Doorkeeper::JWT.configuration.encryption_method.to_s.upcase
        ::JWT.decode(jwt, secret_key, true, { :algorithm => algorithm }).first
      rescue ::JWT::DecodeError
        nil
      rescue ::JWT::ExpiredSignature
        nil
      end

      def new_by_jwt(jwt)
        payload = self.decode(jwt)
        tok = new(
          application_id: nil,
          application_uid: payload['client_uid'],
          resource_owner_id: User.find_by_email(payload['user']['email']).id,
          scopes: payload['scopes'],
          type: payload['type'],
          created_at: Time.at(payload['iat']).to_datetime.utc,
          expires_in: payload['exp'] - payload['iat'],
          use_refresh_token: Doorkeeper.configuration.refresh_token_enabled?
        )
        if payload['type'] == 'access'
          tok.token = jwt
        else
          tok.refresh_token = jwt
        end
        tok
      end

      def by_token(token)
        self.new_by_jwt(token)
      end

      def by_refresh_token(refresh_token)
        self.new_by_jwt(refresh_token)
      end

      def matching_token_for(application, resource_owner_or_id, scopes)
        nil
      end

      # Checks whether the token scopes match the scopes from the parameters or
      # Application scopes (if present).
      #
      # @param token_scopes [#to_s]
      #   set of scopes (any object that responds to `#to_s`)
      # @param param_scopes [String]
      #   scopes from params
      # @param app_scopes [String]
      #   Application scopes
      #
      # @return [Boolean] true if all scopes and blank or matches
      #   and false in other cases
      #
      def scopes_match?(token_scopes, param_scopes, app_scopes)
        (!token_scopes.present? && !param_scopes.present?) ||
          Doorkeeper::OAuth::Helpers::ScopeChecker.match?(
            token_scopes.to_s,
            param_scopes,
            app_scopes
          )
      end

      def find_or_create_for(application, resource_owner_id, scopes, expires_in, use_refresh_token)
        tok = new(
          application_id: application.try(:id),
          application_uid: application.try(:uid),
          resource_owner_id: resource_owner_id,
          scopes: scopes.to_s,
          created_at: Time.now.utc,
          expires_in: expires_in,
          use_refresh_token: use_refresh_token
        )
        tok.generate_tokens
        tok
      end

      def create!(attributes)
        tok = new(attributes)
        tok.generate_tokens
        tok
      end

      def last_authorized_token_for(application_id, resource_owner_id)
        nil
      end

    end

    def revoke
      return unless type.to_sym == :refresh
      RevokedToken.create!(token: refresh_token)
    end


    def revoke_all_for(application_id, resource_owner)
      # no op
    end

    def revoked?
      Doorkeeper::RevokedToken.find_by_token(token)
    end

    def revoke_previous_refresh_token!
      # no op
    end

    # Generates and sets the token value with the
    # configured Generator class (see Doorkeeper.configuration).
    #
    # @return [String] generated token value
    #
    # @raise [Doorkeeper::Errors::UnableToGenerateToken]
    #   custom class doesn't implement .generate method
    # @raise [Doorkeeper::Errors::TokenGeneratorNotFound]
    #   custom class doesn't exist
    #
    def generate_tokens
      generator = Doorkeeper.configuration.access_token_generator.constantize
      self.token = generator.generate(
        resource_owner_id: resource_owner_id,
        scopes: scopes,
        application_uid: application_uid,
        type: :access,
        created_at: created_at,
        expires_in: expires_in
      )
      self.refresh_token = generator.generate(
        resource_owner_id: resource_owner_id,
        scopes: scopes,
        application_uid: application_uid,
        type: :refresh,
        created_at: created_at,
        expires_in: expires_in
      )
    end

    # Access Token type: Bearer.
    # @see https://tools.ietf.org/html/rfc6750
    #   The OAuth 2.0 Authorization Framework: Bearer Token Usage
    #
    def token_type
      'bearer'
    end

    def use_refresh_token?
      @use_refresh_token ||= false
      !!@use_refresh_token
    end

    # JSON representation of the Access Token instance.
    #
    # @return [Hash] hash with token data
    def as_json(_options = {})
      {
        resource_owner_id:  resource_owner_id,
        scopes:             scopes,
        expires_in_seconds: expires_in_seconds,
        application:        { uid: application.try(:uid) },
        created_at:         created_at.to_i
      }
    end

    # Indicates whether the token instance have the same credential
    # as the other Access Token.
    #
    # @param access_token [Doorkeeper::AccessToken] other token
    #
    # @return [Boolean] true if credentials are same of false in other cases
    #
    def same_credential?(access_token)
      application_id == access_token.application_id &&
        resource_owner_id == access_token.resource_owner_id
    end

    # Indicates if token is acceptable for specific scopes.
    #
    # @param scopes [Array<String>] scopes
    #
    # @return [Boolean] true if record is accessible and includes scopes or
    #   false in other cases
    #
    def acceptable?(scopes)
      accessible? && includes_scope?(*scopes)
    end

    private


  end
end
