module Doorkeeper
  module Models
    module Scopes

      def scopes
        OAuth::Scopes.from_string(@scopes)
      end

      def scopes_string
        @scopes
      end

      def includes_scope?(*required_scopes)
        required_scopes.blank? || required_scopes.any? { |s| scopes.exists?(s.to_s) }
      end
    end
  end
end
