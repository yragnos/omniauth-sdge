require "omniauth/sdge/version"
require 'omniauth-oauth2'
require 'multi_json'

module Omniauth
  module Strategies
    # Your code goes here..
    #
    # Authenticate to DigitalOcean via OAuth and retrieve basic user information.
    # Usage:
    #    use OmniAuth::Strategies::Digitalocean, 'consumerkey', 'consumersecret', :scope => 'read write', :display => 'plain'
    #
    class Sdge < OmniAuth::Strategies::OAuth2
      AUTHENTICATION_PARAMETERS = %w(display account state scope)
      BASE_URL = "https://soagwx.sempra.com:3443"

      option :name, "sdge"

      unless OmniAuth.config.test_mode
        option :client_options, {
          :authorize_url => "#{BASE_URL}/DataCustodian/oauth/authorize?DataCustodianID=SDGE&scope=FB_1_3_4_5_8_13_14_18_19_34_35_39_40%3BIntervalDuration%3D900_3600%3BBlockDuration%3DDaily%3BBR%3D1%3BHistoryLength%3D34128000%3BSubscriptionFrequency%3DDaily%3B",
          :token_url => "#{BASE_URL}/DataCustodian/oauth/token",
          :site => BASE_URL
        }
      else
        option :client_options, {
          :authorize_url => "http://localhost:3000/oauth/authorize",
          :token_url => "http://localhost:3000/oauth/token",
          :site => "http://localhost:3000"
        }
      end

      option :authorize_options, AUTHENTICATION_PARAMETERS

      uid do
        access_token.params['info']['uuid']
      end

      info do
        access_token.params['info']
      end

      # Over-ride callback_url definition to maintain
      # compatability with omniauth-oauth2 >= 1.4.0
      #
      # See: https://github.com/intridea/omniauth-oauth2/issues/81
      def callback_url
        callback_path = "https://toustaging.com/auth/sdge/callback"
        # full_host + script_name + callback_path
        # full_host+ script_name "auth/sdge/callback"
      end

      # Hook useful for appending parameters into the auth url before sending
      # to provider.
      def request_phase
        super
      end

      # Hook used after response with code from provider. Used to prep token
      # request from provider.
      def callback_phase
        super
      end

      ##
      # You can pass +display+, +state+ or +scope+ params to the auth request, if
      # you need to set them dynamically. You can also set these options
      # in the OmniAuth config :authorize_params option.
      #
      # /v1/auth/digialocean?display=fancy&state=ABC
      #
      def authorize_params
        super.tap do |params|
          AUTHENTICATION_PARAMETERS.each do |v|
            params[v.to_sym] = request.params[v] if request.params[v]
          end
        end
      end

    end
  end
end
