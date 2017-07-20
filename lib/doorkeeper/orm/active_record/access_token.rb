module Doorkeeper
  class AccessToken
    include ActiveModel::Model
    include AccessTokenMixin

    attr_accessor :application_id, :resource_owner_id, :scopes, :token,
                  :refresh_token, :created_at, :expires_in, :use_refresh_token

    def revoked?
      RevokedTokens.find_by_token(token)
    end

  end
end
