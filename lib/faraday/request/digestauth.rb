# frozen_string_literal: true

module Faraday
  class Request
    # Public: A Faraday middleware to use digest authentication. Since order of
    # middlewares do care, it should be the first one of the Request middlewares
    # in order to work properly (due to how digest authentication works).
    #
    # If some requests using the connection don't need to use digest auth you
    # don't have to worry, the middleware will do nothing.
    #
    # It uses Net::HTTP::DigestAuth to generate the authorization header but it
    # should work with any adapter.
    #
    # Examples:
    #
    #   connection = Faraday.new(...) do |connection|
    #     connection.request :digest, USER, PASSWORD
    #   end
    #
    #   # You can also use it later with a connection:
    #   connection.digest_auth('USER', 'PASSWORD')
    #
    class DigestAuth < Faraday::Middleware
      # Public: Initializes a DigestAuth.
      #
      # app      - The Faraday app.
      # user     - A String with the user to authentication the connection.
      # password - A String with the password to authentication the connection.
      # opts     - A hash with options
      #            - keep_body_on_handshake: if set to truthy, will also send
      #              the original request body
      def initialize(app, user, password, opts = {})
        if user.nil?
          raise ArgumentError, 'Username cannot be nil'
        end
        if password.nil?
          raise ArgumentError, 'Password cannot be nil'
        end

        super(app)
        @user = user
        @password = password
        @opts = opts
        @auth = Net::HTTP::DigestAuth.new
      end

      # Public: Performs a request with digest authentication.
      #
      # On the first request, sends a first request with an empty body
      # to get the authentication headers and then send the same request with
      # the body and authorization header.
      #
      # On subsequent requests, uses the server nonce from the previous request
      # to create the authorization header.
      #
      # env - A Hash with the request environment.
      #
      # Returns a Faraday::Response.
      #
      # rubocop:disable Metrics/AbcSize
      def call(env)
        if @challenge_header
          env[:request_headers]['Authorization'] = header(env, @challenge_header)
          response = @app.call(env)
          return response unless response.status == 401
        end
        response ||= handshake(env)
        # TODO: if request had a payload and handshake succeeded but without
        # the payload, this is probably not what the user expected.
        return response unless response.status == 401
        unless response.headers['www-authenticate'] =~ /Digest +[^\s]+/
          return response
        end

        challenge_header = response.headers['www-authenticate']
        env[:request_headers]['Authorization'] = header(env, challenge_header)
        @app.call(env)
      end
      # rubocop:enable Metrics/AbcSize

      private

      # Internal: Sends the the request with an empry body.
      #
      # env - A Hash with the request environment.
      #
      # Returns a Faraday::Response.
      def handshake(env)
        env_without_body = env.dup
        env_without_body.delete(:body) unless @opts[:keep_body_on_handshake]
        @app.call(env_without_body)
      end

      # Internal: Builds the authorization header with the authentication data.
      #
      # response - A Faraday::Response with the authenticate headers.
      #
      # Returns a String with the DigestAuth header.
      def header(env, challenge_header)
        uri = env[:url].dup
        uri.user = CGI.escape @user
        uri.password = CGI.escape @password

        method = env[:method].to_s.upcase

        unless @challenge_header
          # The first nonce count that net/http/digest_auth generates is 0,
          # which is not accepted by various servers.
          # https://github.com/drbrain/net-http-digest_auth/pull/17
          @auth.auth_header(uri, challenge_header, method)
        end
        @challenge_header = challenge_header

        @auth.auth_header(uri, challenge_header, method)
      end
    end
  end
end
