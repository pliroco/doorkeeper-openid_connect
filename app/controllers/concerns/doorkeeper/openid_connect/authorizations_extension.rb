module Doorkeeper
  module OpenidConnect
    module AuthorizationsExtension
      private

      def pre_auth
        @pre_auth ||= Doorkeeper::OAuth::PreAuthorization.new(
          Doorkeeper.configuration,
          pre_auth_params,
          current_resource_owner,
          request,
        )
      end

      def pre_auth_param_fields
        super.append(:nonce)
      end
    end
  end
end

