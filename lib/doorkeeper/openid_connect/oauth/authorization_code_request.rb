# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module OAuth
      module AuthorizationCodeRequest
        private

        def after_successful_response
          super

          nonce, session_id =
            if (openid_request = grant.openid_request)
              openid_request.destroy!
              [openid_request.nonce, openid_request.session_id]
            end

          id_token = Doorkeeper::OpenidConnect::IdToken.new(access_token, nonce, session_id)
          @response.id_token = id_token
        end
      end
    end
  end

  OAuth::AuthorizationCodeRequest.prepend OpenidConnect::OAuth::AuthorizationCodeRequest
end
