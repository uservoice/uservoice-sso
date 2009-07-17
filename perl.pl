#!/usr/bin/perl 
# Based on code by Corris Randall <corris@cpan.org>

package UservoiceToken;

use Crypt::CBC;
use Digest::SHA;
use URI::Escape;
use MIME::Base64;
use JSON;

# call as:
# my $user_data = { guid => '<%= example_user[:guid] %>', display_name => '<%= example_user[:display_name] %>', expires => '<%= example_user[:expires].to_s(:db) %>' };
# my $token = new UservoiceToken;
# $token->create($user_data)

sub new {
  my $class = shift;	
  my $self = {};

  $self->{'account_key'} = "YOUR_ACCOUNT_KEY";
  $self->{'api_key'} = 'YOUR_API_KEY';
  $self->{'iv'} = "OpenSSL for Ruby";
  $self->{'meth'} = "Crypt::Rijndael";

  bless $self, $class;
  return $self;
}

sub create {
  my $self = shift;
  my $hash = shift;

  my $json = new JSON;
  my $data = $json->encode($hash);

  my $sha = new Digest::SHA;
  $sha->add( $self->{'api_key'} . $self->{'account_key'} );
  my $key = substr($sha->hexdigest,0,32);

  # xor the iv into the first 16 bytes.
  foreach my $i ( 0 .. 15 ) {
    substr($data,$i,1) ^= substr($self->{'iv'},$i,1);
  }

  # create cipher object
  $obj = Crypt::CBC->new (
  -key => pack("H*",$key),
  -literal_key => 1,
  -header => "none",
  -keysize => 16,
  -iv => $self->{'iv'},
  -cipher => $self->{'meth'}
  );

  # encrypt data
  $encdata = $obj->encrypt( $data );
  return uri_escape(encode_base64( $encdata ));
  }
