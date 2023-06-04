require "thread"

class StatusManager
	def initialize(status)
		@status = status
		@text = ""
		@queue = Queue.new
	end

	def add_status(text)
		@queue.push(text)
	end

	def start
		Thread.start do
			loop do
				@status.text = @queue.pop
				sleep 0.1
			end
		end
	end
end
