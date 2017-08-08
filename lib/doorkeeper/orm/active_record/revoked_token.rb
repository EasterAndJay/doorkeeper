module Doorkeeper
  class RevokedToken < ActiveRecord::Base
    JWT_REGEX = /\A[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?\z/.freeze
    validates_presence_of :token
    validates_format_of :token, :with => JWT_REGEX

    self.table_name = "#{table_name_prefix}oauth_revoked_tokens#{table_name_suffix}".to_sym

  end
end
