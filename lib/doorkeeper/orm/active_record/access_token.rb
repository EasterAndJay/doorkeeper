module Doorkeeper
  class AccessToken
    include ActiveModel::Model
    include AccessTokenMixin

    attr_accessor :application_id, :application_uid, :resource_owner_id,
                  :scopes, :token, :refresh_token, :created_at, :expires_in,
                  :use_refresh_token, :type

    def self.delete_all_for(application_id, resource_owner)
      # no op
    end
    private_class_method :delete_all_for

    # Searches for not revoked Access Tokens associated with the
    # specific Resource Owner.
    #
    # @param resource_owner [ActiveRecord::Base]
    #   Resource Owner model instance
    #
    # @return [ActiveRecord::Relation]
    #   active Access Tokens for Resource Owner
    #
    def self.active_for(resource_owner)
      # no op
    end

    # ORM-specific order method.
    def self.order_method
      :order
    end

    def self.refresh_token_revoked_on_use?
      false
    end

    # ORM-specific DESC order for `:created_at` column.
    def self.created_at_desc
      'created_at desc'
    end

  end
end
