from __future__ import print_function
import argparse
import collections
import logging
import multiprocessing
import os
import shutil
import subprocess
import sys
import time
import ntpath
from textwrap import dedent, wrap

nul = open(os.devnull, 'wb')

AFLShowMapResult = collections.namedtuple(
    'AFLShowMapResult', [
        'returncode', 'path', 'filesize', 'tuples'
    ]
)

class AFLShowMapWorker(object):
    '''This class abstracts away the interaction with afl-showmap.exe
    and plays nice with the multiprocessing module'''
    def __init__(self, args):
        self.args = args

    @staticmethod
    def _to_showmap_options(args, trace_name = '-'):
        '''Takes the argparse namespace, and convert it to the list of options used
        to invoke afl-showmap.exe'''
        r = [
            'afl-showmap.exe', '-q', '-o', trace_name
        ]

        if args.time_limit > 0:
                r.extend(['-t', '%d' % args.time_limit])
        else:
            r.extend(['-t', 'none'])

        if args.memory_limit > 0:
                r.extend(['-m', '%dk' % args.memory_limit])
        else:
            r.extend(['-m', 'none'])

        r.extend(['-p', args.target_module])

        if args.edges_only:
            r.append('-e')

        r.append('--')
        r.extend(args.target_cmdline)
        return r

    def __call__(self, input_file):
        '''Runs afl-showmap.exe on a specific target and extracts
        the tuples from the generated trace'''
        current_process = multiprocessing.current_process()
        fileread = None
        if self.args.file_read is not None:
            # It means that the target expects to have '@@' replaced with a
            # constant path file. First step, is to copy the input to
            # this location
            fileread = self.args.file_read.replace(
                '@@', current_process.name
            )
            if os.path.isfile(fileread):
                os.remove(fileread)
            shutil.copyfile(input_file, fileread)

        trace_name = ntpath.basename(input_file) + '.trace.bin'
        opts = AFLShowMapWorker._to_showmap_options(self.args, trace_name)
        # If we have a '@@' marker in the command line, it has to be replaced
        # by an actual file. It is either directly the input testcase, or the
        # file specified by the -f option.
        if opts.count('@@') > 0:
            idx = opts.index('@@')
            opts[idx] = input_file if fileread is None else fileread
            stdin = nul
        else:
            # handle inputs via stdin as opposed to '@@' & -f
            stdin = open(input_file if fileread is None else fileread)

        # Make sure there isn't a trace that hasn't been properly cleaned
        if os.path.isfile(trace_name):
            os.remove(trace_name)

        p = subprocess.Popen(opts, stdin=stdin, stdout=nul, stderr=nul)
        p.wait()

        if fileread is not None:
            # Clean it up
            os.remove(fileread)

        # Read the trace file and populate the tuple store
        tuples = {}
        if os.path.isfile(trace_name):
            if os.path.getsize(trace_name) == 0:
                logging.error('[!] %s trace file is empty', trace_name)
            with open(trace_name, 'r') as f:
                for line in f.readlines():
                    tuple_id, hitcount = map(int, line.split(':', 1))
                    tuples[tuple_id] = hitcount

            # Clean it up
            os.remove(trace_name)
        return AFLShowMapResult(
            p.returncode, input_file,
            os.path.getsize(input_file), tuples
        )

def setup_argparse():
    '''Sets up the argparse configuration.'''
    parser = argparse.ArgumentParser(
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = '\n'.join(wrap(dedent(
            '''
            Examples of use:
             * Typical use
              afl-cmin.py -t 5000 -i in -o min -p demo.dll -- test.exe
             * Dry-run, keep crashes only with 4 workers with a working directory:
              afl-cmin.py -C --dry-run -w 4 --working-dir D:\\dir -i in -i C:\\fuzz\\in -o min -p demo.dll -- test.exe @@
             * Read specific file on specific location
              afl-cmin.py -t 5000 -i in -o min -f foo.ext -p m.dll -- test.exe @@
             * Read from specific file with pattern
              afl-cmin.py -t 5000 -i in -o min -f prefix-@@-foo.ext -p demo.dll -- test.exe @@
            '''
        ), 100, replace_whitespace = False))
    )

    group = parser.add_argument_group('basic parameters')
    group.add_argument(
        '-i', '--input', action = 'append', required = True,
        metavar = 'dir', help = 'input directory with the starting corpus.' \
        'Multiples input directories are supported'
    )
    group.add_argument(
        '-o', '--output', required = True,
        metavar = 'dir', help = 'output directory for minimized files'
    )
    group.add_argument(
        '-n', '--dry-run', action = 'store_true', default = False,
        help = 'do not really populate the output directory'
    )
    group.add_argument(
        '--working-dir', default = os.getcwd(),
        metavar = 'dir', help = 'directory containing afl-showmap.exe,' \
        'the target binary, etc.'
    )
    group.add_argument(
        '-v', '--verbose', action = 'store_const',
        default = logging.INFO, const = logging.DEBUG
    )

    group = parser.add_argument_group('instrumentation settings')
    group.add_argument(
        '-p', '--target_module', required = True,
        metavar = 'module', help = 'module which contains the target function to be fuzzed'
    )

    group = parser.add_argument_group('execution control settings')
    group.add_argument(
        '-t', '--time-limit', type = int, default = 0,
        metavar = 'msec', help = 'timeout for each run (none)'
    )
    group.add_argument(
        '-m', '--memory-limit', type = int, default = 0,
        metavar = 'kb', help = 'memory limit for each run (none)'
    )
    group.add_argument(
        '-f', '--file-read', default = None,
        metavar = 'file', help = 'location read by the fuzzed program. ' \
        'Usage of @@ is encouraged to keep parallelization possible'
    )

    group = parser.add_argument_group('minimization settings')
    group.add_argument(
        '-C', '--crash-only', action = 'store_true', default = False,
        help = 'keep crashing inputs, reject everything else'
    )
    group.add_argument(
        '-e', '--edges-only', action = 'store_true', default = False,
        help = 'solve for edge coverage only, ignore hit counts'
    )
    group.add_argument(
        '-w', '--workers', type = int, default = 1,#multiprocessing.cpu_count(),
        metavar = 'n', help = 'The number of worker processes (default: cpu count)'
    )
    parser.add_argument(
        'target_cmdline', nargs = argparse.REMAINDER,
        help = 'target command line'
    )
    return parser.parse_args()


def main(argc, argv):
    print('Corpus minimization tool for pe-afl')
    print('Based on corpus minimization tool for WinAFL by <0vercl0k@tuxfamily.org>')
    print('Based on WinAFL by <ifratric@google.com>')
    print('Based on AFL by <lcamtuf@google.com>')

    args = setup_argparse()
    logging.basicConfig(
        stream=sys.stdout,
        level = logging.DEBUG,
        format = '%(message)s'
    )
    
    # Interestingly enough, if the user uses '.. -- target.exe -option foo ..'
    # argparse will add '--' in the target_cmdline option, so we need to
    # strip it off manually here.
    if [x for x in args.target_cmdline][0] == '--':
        del args.target_cmdline[0]

    if os.path.isdir(args.working_dir) is False:
        logging.error(
            '[!] The working directory %r is not a directory', args.working_dir
        )
        return 1

    os.chdir(args.working_dir)
    logging.info('[+] CWD changed to %s.', args.working_dir)

    # Make sure afl-showmap.exe are present in the CWD
    if os.path.isfile('afl-showmap.exe') is False:
        logging.error(
            '[!] afl-showmap.exe need to be in %s.',
            args.working_dir
        )
        return 1

    # Make sure the output directory doesn't exist yet
    if args.dry_run is False and os.path.isdir(args.output):
        logging.error(
            '[!] %s already exists, please remove it to avoid data loss.',
            args.output
        )
        return 1

    # Go get all the input files we want to have a look at
    assert all(os.path.isdir(i) for i in args.input)
    logging.debug(
        'Inspecting the following directories: %s',
        ', '.join(args.input)
    )
    inputs = []
    for path in args.input:
        for root, dirs, files in os.walk(path):
            for file_ in files:
                inputs.append(os.path.join(root, file_))

    # Do a dry run with the first file in the set
    logging.info('[*] Testing the target binary...')
    f = AFLShowMapWorker(args)
    results = map(f, (inputs[0], inputs[0]))
    if (results[0] != results[1]) or (len(results[0].tuples) == 0):
        logging.error('[!] Dry-run failed, execution has some problem:')
        logging.error(
            '  Tuples matching? %r',
            results[0].tuples == results[1].tuples
        )
        logging.error(
            '  Return codes matching? %r',
            results[0].returncode == results[1].returncode
        )
        logging.error(
            '  Tuples non-empty? %r',
            results[0].tuples != {}
        )
        return 1

    logging.info('[+] OK, %d tuples recorded.', len(results[0].tuples))

    nprocesses = args.workers
    if args.file_read is not None and '@@' not in args.file_read:
        # Check if the file already exists, we don't want to overwrite a
        # potential interesting test case.
        if os.path.isfile(args.file_read):
            logging.error(
                '[!] %s already exists, please remove it to avoid data loss.',
                args.file_read
            )
            return 1

        # If you are providing -f, but doesn't specify '@@' in the command line
        # of the target, it might be a sign that you are doing something wrong.
        if '@@' not in args.target_cmdline:
            logging.warn(
                "[ ] You specified the -f option without using '@@' in your "
                "command line, this does not sound right."
            )

        logging.info('[+] Worker pool size: 1 (because no "@@" in the -f option)..')
        # Keep in mind that if you want the input files to be named and placed
        # by your liking by specifying -f path/foo.ext we have to set the pool
        # size to 1 in order to make it work.
        nprocesses = 1

    # Record stats about the original input set.
    #  The aggregated size of every input files.
    totalsize = 0
    #  The size of the input set.
    inputs_len = len(inputs)

    logging.info(
        '[+] Found %d test cases across: %s.',
        inputs_len, ', '.join(args.input)
    )

    t0 = time.time()
    logging.info('[*] Instantiating %d worker processes.', nprocesses)
    p = multiprocessing.Pool(processes = nprocesses)
    # This tracks every unique tuples and their popularities
    uniq_tuples = collections.Counter()
    # This will associate a tuple with the currently fittest file exercising
    # this particular tuple.
    candidates = {}
    # This tracks every files that triggered a hang.
    hang_files = []
    # This tracks every files that triggered a crash.
    crash_files = []
    # This tracks every files that generated an empty set of tuples.
    # You might get those if the dynamically instrumented target module doesn't
    # get hit because the testcase is so malformed that it won't pass a
    # function called before for example; hence will return an empty tuple set.
    empty_tuple_files = []
    # The default return code is no crash.
    wanted_returncode = 0
    if args.crash_only:
        logging.info('[+] Crash only mode enabled.')
        wanted_returncode = 2

    # Counter tracking how many files we have been through already.
    i = 1
    for result in p.imap_unordered(
        AFLShowMapWorker(args),
        inputs
    ):
        print('\rProcessing file %d/%d...' % (i, inputs_len), end=' ')
        i += 1
        # If the set of tuples is empty, something weird happened
        if len(result.tuples) == 0:
            logging.debug(
                '[x] The input file %s generated an empty set of tuples,'
                ' skipping it (ret = %d).',
                result.path, result.returncode
            )
            empty_tuple_files.append(result.path)
            continue

        if result.returncode != wanted_returncode:
            if result.returncode == 1:
                hang_files.append(result.path)

            # If the mode crash only is enabled, we track the non-crashing
            # test cases in the same tuple.
            if (result.returncode == 2 and args.crash_only is False) or \
               (result.returncode == 0 and args.crash_only):
                crash_files.append(result.path)

            if args.crash_only is False:
                logging.debug(
                    '[x] The input file %s triggered a %s, skipping it. ',
                    result.path,
                    'hang' if result.returncode == 1 else 'crash'
                )
            else:
                logging.debug(
                    '[x] The input file %s triggered a %s, skipping it.',
                    result.path,
                    'hang' if result.returncode == 1 else 'non crash'
                )

            continue

        totalsize += result.filesize

        # Generate the list of unique tuples while processing the results,
        # also keep track of their popularities.
        uniq_tuples.update(result.tuples.keys())

        # Keep an updated dictionary mapping a tuple to the fittest file
        # of all the paths.
        for tuple_id, tuple_hitcount in result.tuples.iteritems():
            fileinfo = {
                'size' : result.filesize,
                'path' : result.path,
                'tuples' : result.tuples,
                'hitcount' : tuple_hitcount
            }

            if tuple_id in candidates:
                candidate = candidates[tuple_id]
                # If the candidate has a higher hitcount, we keep it.
                if tuple_hitcount > candidate['hitcount']:
                    candidates[tuple_id] = fileinfo
                elif tuple_hitcount == candidate['hitcount']:
                    # If the candidate has the same hitcount, but a
                    # smaller size, we keep it.
                    if result.filesize < candidate['size']:
                        candidates[tuple_id] = fileinfo
                    elif result.filesize == candidate['size']:
                        # If the candidate has the same hitcount and
                        # size, but exercise a bigger number of tuples,
                        # we keep it.
                        if len(result.tuples) > len(candidate['tuples']):
                            candidate[tuple_id] = fileinfo
            else:
                candidates[tuple_id] = fileinfo

    len_crash_files, len_hang_files, len_empty_tuple_files = map(
        len, (crash_files, hang_files, empty_tuple_files)
    )
    effective_len = inputs_len - (
        len_crash_files + len_hang_files + len_empty_tuple_files
    )
    print()

    len_uniq_tuples = len(uniq_tuples)
    logging.info(
        '[+] Found %d unique tuples across %d files',
        len_uniq_tuples, effective_len
    )
    if len_hang_files > 0:
        logging.info('  - %d files triggered a hang', len_hang_files)
        for hang_file in hang_files:
            logging.debug('    - %s generated a hang', hang_file)

    if len_crash_files > 0:
        logging.info(
            '  - %d files %s a crash',
            len_crash_files,
            'did not trigger' if args.crash_only else 'triggered'
        )
        for crash_file in crash_files:
            logging.debug('    - %s generated a crash', crash_file)

    if len_empty_tuple_files > 0:
        logging.info(
            '  - %d files resulted in an empty tuple set',
            len_empty_tuple_files
        )
        for empty_tuple_file in empty_tuple_files:
            logging.debug('    - %s generated an empty tuple', empty_tuple_file)

    logging.info('[*] Finding best candidates for each tuple...')

    # Using the same strategy than in afl-cmin, quoting lcamtuf:
    # '''
    # The "best" part is understood simply as the smallest input that
    # includes a particular tuple in its trace. Empirical evidence
    # suggests that this produces smaller datasets than more involved
    # algorithms that could be still pulled off in a shell script.
    # '''
    minset = []
    minsetsize = 0
    remaining_tuples = list(uniq_tuples)
    for tuple_ in uniq_tuples:
        if tuple_ not in remaining_tuples:
            # It means we already deleted this tuple, as it was exercised
            # as part of another test case.
            continue

        # Pick the current best file candidate for this tuple.
        candidate = candidates[tuple_]

        # Remove the other tuples also exercised by the candidate
        # from the remaining_tuples list.
        for tuple_exercised in candidate['tuples'].iterkeys():
            # Remove the tuples exercised if we have not
            # removed them already from the
            # remaining_tuples list.
            if tuple_exercised in remaining_tuples:
                remaining_tuples.remove(tuple_exercised)

        # Keep track of the final minset and its size.
        minset.append(candidate['path'])
        minsetsize += candidate['size']

        # We are now done with this tuple, we can get rid of it.
        del candidates[tuple_]

        print('\rProcessing tuple %d/%d...' % (
            len_uniq_tuples - len(remaining_tuples),
            len_uniq_tuples
        ), end=' ')

        # If we don't have any more tuples left, we are done.
        if len(remaining_tuples) == 0:
            break

    print()
    logging.info('[+] Original set was composed of %d files', inputs_len)
    logging.info(
        '[+] Effective set was composed of %d files (total size %d MB).',
        effective_len, (totalsize / 1024) / 1024
    )
    logging.info(
        '[+] Narrowed down to %d files (total size %d MB).',
        len(minset), (minsetsize / 1024) / 1024
    )

    if args.dry_run is False:
        logging.info(
            '[*] Saving the minset in %s...', os.path.abspath(args.output)
        )
        os.mkdir(args.output)
        for file_path in minset:
            shutil.copy(file_path, args.output)

    logging.info('[+] Time elapsed: %d seconds', time.time() - t0)
    return 0

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))
