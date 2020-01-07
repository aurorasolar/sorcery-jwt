module Sorcery
  module Controller
    module Submodules
      module Jwt
        def self.included(base)
          base.send(:include, InstanceMethods)
          Config.login_sources << :login_from_jwt
        end

        module InstanceMethods
          protected

          def login_from_jwt
            user = decoded_token.first.slice("id", "email")

            @current_user = user_class.find_by(user)
            auto_login(@current_user) if @current_user
            @current_user
          rescue JWT::DecodeError, JWT::ExpiredSignature
            @current_user = false
          end

          def login_and_issue_token(*credentials)
            return unless (user = user_class.authenticate(*credentials))

            @current_user = user
            auto_login(@current_user)

            # Set '@token' so 'token' can be used immediately after logging in, instead of only
            # in authenticated requests.
            @token = user_class.issue_token(id: @current_user.id, email: @current_user.email)
          end

          private

          def token
            # Fallback to @token in case the user just logged in
            return @token unless authorization_header

            authorization_header.split(" ").last
          end

          def authorization_header
            @authorization_header ||= request.headers["X-Auth-Token"]
          end

          def decoded_token
            user_class.decode_token(token)
          end

          # [Optional] The "jti" (JWT ID) claim is a unique identifier for the JWT (see RFC 7519).
          def token_id
            decoded_token.first['jti']
          end
        end
      end
    end
  end
end
