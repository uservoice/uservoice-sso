require 'rubygems'
require 'ezcrypto'
require 'json'
require 'cgi'
require 'base64'

module Uservoice
  class Token
    attr_accessor :data
    
    USERVOICE_ACCOUNT_KEY = "<%= account_key %>"
    USERVOICE_API_KEY = "<%= api_key %>"
    
    def initialize(options = {})
      {:expires => (Time.now + 5 * 60).to_s}.merge!(options)
      
      key = EzCrypto::Key.with_password USERVOICE_ACCOUNT_KEY, USERVOICE_API_KEY
      encrypted = key.encrypt(options.to_json)
      @data = CGI.escape(Base64.encode64(encrypted)).gsub(/\n/, '')
    end
    
    def to_s
      @data
    end
  end
end