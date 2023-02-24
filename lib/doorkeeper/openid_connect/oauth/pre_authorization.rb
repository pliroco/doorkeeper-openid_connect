# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module OAuth
      module PreAuthorization
        attr_reader :nonce, :session_id

        def initialize(server, attrs = {}, resource_owner = nil, request = nil)
          super(server, attrs, resource_owner)
          @nonce = attrs[:nonce]
          @session_id = Doorkeeper::OpenidConnect.configuration.session_id&.call(request).to_s
        end

        # NOTE: Auto get default response_mode of specified response_type if response_mode is not
        #   yet present. We can delete this method after Doorkeeper's minimize version support it.
        def response_on_fragment?
          return response_mode == 'fragment' if response_mode.present?

          grant_flow = server.authorization_response_flows.detect do |flow|
            flow.matches_response_type?(response_type)
          end

          grant_flow&.default_response_mode == 'fragment'
        end
      end
    end
  end

  OAuth::PreAuthorization.prepend OpenidConnect::OAuth::PreAuthorization
end
