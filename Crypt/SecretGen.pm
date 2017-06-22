package Crypt::SecretGen;
use strict;
use Exporter 'import';
use vars qw ($VERSION);

$VERSION = '0.01';

=head1 AUTHORS

Jeremy Melanson <zish[at]systemhalted[dot]com>

=head1 COPYRIGHT

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU Lesser General Public License 3.0
(or higher, at your discretion).

=cut

#-- These are "private" variables, that can only be accessed from within
# a blessed object itself.
# - Making these "private" makes changing of these values more difficult after
#   declaration.
# - Making them HASHes allows multiple entries to be referenced, instead of
#   accessing one across all declared objects.
#   (Required since these variables are specific to a file, and not an object).
#
# ** The catch is that these are accessible across all references, but they **
# ** should be reasonably safe, if this file has not been tampered with,    **
# ** and Crypt::SecretGen is not extended by untrusted code.                **
#
# TODO:
#
my $rnd_fh	= {};	# Holder for per-reference Random generator filehandles.
my $opts		= {};	# Holder for per-reference options.
# TODO:
my $errors	= {};	# Holder for per-reference error lists.

use constant {
	#-- Put a name to an error level.
	ERR_LEVELS => [
		'INFORMATIONAL', 'WARNING', 'ERROR', 'CRITICAL_ERROR', 'FATAL_ERROR'
	],
};

=head1 SUBROUTINES

=over 4

=item new {options}

Create a new Crypt::SecretGen object, with a new random generator filehandle
and new options.

Available Options:

=over 4

=item length - Default secret length to return

Defaults to 12 characters.

=item error_level_fail - Minimum error level to suppress output of a secret

Value should be between 0 and 4.

Defaults to 3 (Critical).

=item rndsrc - Device or file to use as random number generation source

Defaults to '/dev/urandom'.

B<'-' can be specified to use STDIN>

=back

=cut

sub new {
	my $self = bless ({}, shift);

	$opts->{$self} = $_[0];
	$self->_check_opts ($opts->{$self});

	return ($self);
} # END sub new

=item _fh

Return the filehandle associated with the current blessed reference.

=cut

sub _fh {
	my $self = shift;

	return ($rnd_fh->{$self});
} # END sub _fh

=item get_secret [LENGTH]

Generate and return randomized string.

Optionally specify a LENGTH to override $opts->{length}. Otherwise defaults
to what is set in $opts->{length}.

=cut

sub get_secret {
	my $self = shift;

	my $len = $_[0];
	$len = $opts->{$self}->{length} if (!$len);

	#-- Holder for characters retrieved. Will be length of requested password.
	my $char_list;


	#-- Compile the 'n' valid char lists into a big, single string.
	my $optional_chars;
	foreach my $v (keys (%{$opts->{$self}->{v}})) {

		if ($opts->{$self}->{v}->{$v} eq 'n') {
			$optional_chars .= $v; next;
		}

		$char_list .= $self->gen_rnd_str ($opts->{$self}->{v}->{$v}, $v);
	}

	#-- Add some more  characters from the 'optional' list if we need more.
	if ($len > length ($char_list)) {
		$char_list .= $self->gen_rnd_str (
			($len - length ($char_list)), $optional_chars
		);
	}

	my $output = $self->shuffle ($char_list);
	unless ($self->last_error_level () >= $opts->{$self}->{error_level_fail}) {
		return ($output);
	}

	return (undef);
} # END sub get_secret

=item shuffle INPUT_STRING

Randomize the character sequence of an input string.

Uses Fisher-Yates shuffle algorithm
[L<Wikipedia|https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle>]
[L<programming-algorithms.net|http://www.programming-algorithms.net/article/43676/Fisher-Yates-shuffle>]

=cut

sub shuffle {
	my $self = shift;

	my @input = split ('', $_[0]);
	for (my $l=0; $l<=$#input; $l++) {
		my $r = int ($self->get_rnd_num (0, $l));
		@input[$l,$r] = @input[$r,$l];
	}

	return join ('', @input);
} # END sub shuffle

=item gen_rnd_str LENGTH, VALID_CHARS

Generate a random string of specified length, containing only a limited
set of characters.

B<TODO:> Introduce a way to support unicode characters as valid items.

=cut

sub gen_rnd_str {
	my $caller = [caller];
	my $self = shift;

	my ($len, $valid_chars) = ($_[0], $_[1]);

	if (!length ($valid_chars)) {
		$self->_err ('[File "'.$caller->[1].'", Pkg: '.$caller->[0].
			', Line '.$caller->[2].
			'] No character list provided to gen_rnd_str.', 3);
		return (undef);
	}

	my $output;

	#-- Turn $valid_chars into range regex. Makes it easier to remove duplicates.
	$valid_chars = '[' . $valid_chars . ']';
	for (1..$len) {
		my $char; # Holder for a character retrieved.
		$char = chr ($self->read_rnd_src ()) until ($char =~ /$valid_chars/);
		$output .= $char;
	}

	return ($output);
} # END sub gen_rnd_str

=item read_rnd_src RANGE_START, RANGE_END

Read a single byte from the 'random' source filehandle. The byte value returned
must be within the numeric range specified by RANGE_START and RANGE_END.

B<TODO:> Error checking for RANGE_START and RANGE_END.
Both must be numeric, and RANGE_END must be larger or equal to RANGE_START.

B<IDEA:> Perhaps also allow entering non-numeric bytes (eg. use range
of ASCII strings by converting to and from ord() if the values are
sigle-byte, and non-numeric).

B<TODO:> Throw warning if RANGE_START is less than 0, or if RANGE_END
is greater than 255. Set to 0 and 255, respectively, if they are.

=cut

sub read_rnd_src {
	my $caller = [caller];
	my $self = shift;

	my ($range_start, $range_end) = ($_[0], $_[1]);

	#--- Completely die if we're in a 'fatal' error state.
	if ($self->high_error_level () >= $self->error_level_fail ()) {
		$self->_err ('Currently in fatal state (Fatal [high_error_level] is '.
			$self->high_error_level ().'). Not continuing.', 4);

		die ('[File "'.$caller->[1].'", Pkg: '.$caller->[0].', Line '.
			$caller->[2].']'."\nERRORS: \n\n".$self->errors_str ());
	}

	#--- Default valid characters are 0-9, A-Z, and a-z.
	$range_start = 33 if (!$range_start);
	$range_end = 127 if (!$range_end);
	$range_start = 0 if ($range_start eq 'n');

	if (!$rnd_fh->{$self}) {
		if ($opts->{$self}->{rndsrc} eq "-") {
			$rnd_fh->{$self} = *STDIN;
		} else {
			#-- Try to open the file for reading. Capture the error if it fails.
			eval {
				if (!open ($rnd_fh->{$self}, "<", $opts->{$self}->{rndsrc})) {
					die ($!);
				}
			};
			if ($@) {
				$self->_err ("Error reading Rnd source '".
					$opts->{$self}->{rndsrc}."': ".$@, 4);
			}

		}
	}

	my $read_buf;
	my $ord = -20;
	until ($ord >= $range_start && $ord <= $range_end) {
		read ($rnd_fh->{$self}, $read_buf, 1); $ord = ord ($read_buf);
	}

	return ($ord);
} # END sub read_rnd_src

=item get_rnd_num RANGE_START, RANGE_END

Generate a randomized integer, within the numeric range specified
by RANGE_START and RANGE_END.

B<TODO:> Either determine how to allow RANGE_START and/or RANGE_END
to be negative, or disable support for negative numbers.
I<This is not a requirement for password generation, but may be useful
for other purposes.>

=cut

sub get_rnd_num {
	my $self = shift;

	my ($range_start, $range_end) = ($_[0], $_[1]);
	$range_start = 0 if (!$range_start); $range_end = 255 if (!$range_end);

	my $start_modulus = int ($range_end / 256);
	my $last_bit	= ($range_end - (($start_modulus * 256)));
	my $mod_loops = (($self->read_rnd_src ('n', 255) / 256) * $start_modulus);

	my $sum;
	for (my $c=0; $c<=$mod_loops; $c++) {
		$sum += $self->read_rnd_src ('n',255);
	}

	my $use_last_bit = int ($self->read_rnd_src ('n', 255) / 128);
	$sum += $self->read_rnd_src ('n', $last_bit) if ($use_last_bit);

	return ($sum);
} # END sub get_rnd_num

=item _set_valid_chars

Internally-used subroutine to initilaize lists of 'valid' characters to use
for generating the new secret string.

Options are retrieved from $opts->{$self}.

=cut

sub _set_valid_chars {
	my $self = shift;

	#-- Keep track of sum of required characters from CLI
	# (Make sure it's not bigger than the password length).
	my $req_chars_count = 0;
	#-- Nonzero when we have at least 1 non-required character to use.
	my $has_optional_chars;

	unless ($opts->{$self}->{nodefault}) {
		my $default_list;
		#-- Default valid characters are 0-9, A-Z, and a-z.
		$default_list .= chr ($_)
			for (ord('0')..ord('9'), ord('a')..ord('z'), ord('A')..ord('Z'));
		$opts->{$self}->{v}->{$default_list} = 'n';
		$has_optional_chars = 1;
	}

	foreach my $list (@{$opts->{$self}->{charlists}}) {
		#-- Extract the count requirement for the given character list.
		my $num_required;
		if ($list =~ s/^(\d+)://) {
			$num_required = $1;
		} else {
			$has_optional_chars = 1;
		}
		if (my @ranges = ($list =~ /((?<!\\)\\.(\.\.|\-)(\\?.))/g)) {
			for (my $c=0; $c<=$#ranges; $c+=3) {
				my $cur_range = $ranges[$c];

				#-- Reverse the character range values, if byte val of START
				# is greater than byte val of END.
				# Not -entirely- needed, but a nice convenience measure.
				if (ord ($ranges[$c+1]) > ord ($ranges[$c+3])) {
					$cur_range = $ranges[$c+3] . $ranges[$c+2] . $ranges[$c+1];
				}
				if (ord ($ranges[$c+1]) > ord ($ranges[$c+3])) {
					$self->_err (
						'Byte val of START larger than END for char range "'.
						$cur_range.'". Range used in reverse.'
					);
					$cur_range = $ranges[$c+3] . $ranges[$c+2] . $ranges[$c+1];
				}
				$list .= $cur_range;
			}
		}
		$opts->{$self}->{v}->{$list} = ($num_required || 'n');
		$req_chars_count += $num_required;
	}

	if ($req_chars_count > $opts->{$self}->{length}) {
		$self->_err ('Sum of required char ('.$req_chars_count.
			') exceeds requested secret length ('.
			$opts->{$self}->{length}.').', 2
		);
	}

	if (($req_chars_count < $opts->{$self}->{length}) && (!$has_optional_chars)) {
		$self->_err ('Total required char count ('.$req_chars_count.')'.
			' must equal requested secret length ('.$opts->{$self}->{length}.
			") when no optional char lists are provided.", 3
		);
	}

} # END sub _set_valid_chars

=item _err ERR_MSG ERR_LEVEL

Append to internal error list. Optionally include error level for message.

=cut

sub _err {
	my $self = shift;

	my ($msg, $level) = @_;
	$level = 1 if (!$level); #-- Default level is 1 (warning).

	#-- Init the errors branch if it's not there.
	$self->{errors} = bless ([], ref ($self).'::Errors') if (!$self->{errors});

	my $err_msg = {
		msg => $msg, level => $level, level_str => ERR_LEVELS->[$level]
	};

	$err_msg = bless ($err_msg, ref ($self).'::Errors::Error');

	push (@{$self->{errors}}, $err_msg);

	$self->{high_error_level} = 0 if (!$self->{high_error_level});
	$self->{high_error_level} = $level if ($level > $self->{high_error_level});
} # END sub _err

=item errors_list

Return internal error list as an array.

=cut

sub errors_list {
	my $self = shift;

	return (@{$self->{errors}}) if ($self->{errors});
	return (undef);
} # END sub errors_list

=item errors_str

Return internal error list as a string, with each error
separated by carriage-returns.

=cut

sub errors_str {
	my $self = shift;

	my $output;
	foreach my $e (@{$self->{errors}}) {
		$output .= $e->{level_str}.'('.$e->{level}.'): '.$e->{msg}."\n";
	}

	return ($output);
} # END sub errors_str

=item last_error_str

Return message from most recent error.

=cut

sub last_error_str {
	my $self = shift;

	return ($self->{errors}->{$#{$self->{errors}}}->{msg}) if ($self->{errors});
	return (undef);
} # END sub last_error

=item last_error_level

Return numeric error level from most recent error.

=cut

sub last_error_level {
	my $self = shift;

	if ($self->{errors}) {
		return ($self->{errors}->[$#{$self->{errors}}]->{level});
	}
	return (0);
} # END sub last_error_level

=item high_error_level

Return numeric error level from highest error reached since $self->clear_errors
was last called.

=cut

sub high_error_level {
	my $self = shift;

	return ($self->{high_error_level}) if ($self->{high_error_level});
	return (0);
} # END sub highest_error_level

=item error_level_fail

Return value got error_level_fail, which determines the level to consider
as "fatal".

=cut

sub error_level_fail {
	my $self = shift;

	if ($opts->{$self}->{error_level_fail}) {
		return ($opts->{$self}->{error_level_fail});
	}
	return (0);
} # END sub error_level_fail

=item clear_errors

Clear the recorded error information.

=cut

sub clear_errors {
	my $self = shift;

	if ($self->{errors}) {
		undef ($self->{errors});
		undef ($self->{high_error_level});
	}
} # END sub clear_errors

=item _check_opts

Internal subroutine to validate the options in $opts->{$self}.

=back

=cut

sub _check_opts {
	my $self = shift;

	#-- Default password length to 12 characters.
	$opts->{$self}->{length} = 12 if (!$opts->{$self}->{length});

	#-- Fail to return a secret, if this error level is met
	# (default = critical).
	if (!$opts->{$self}->{error_level_fail}) {
		$opts->{$self}->{error_level_fail} = 3;
	}

	#-- Random number generation device source.
	if (!$opts->{$self}->{rndsrc}) { $self::rndsrc = "/dev/urandom"; }
	else { $self::rndsrc = $opts->{$self}->{rndsrc}; }

	my $char_lists = [];
	$self->_set_valid_chars ($opts->{$self});
} # END sub _check_opts

END {
	foreach my $fh (keys (%{$rnd_fh})) {
		close ($rnd_fh->{$fh});
	}
}

1;

__END__

