module Keyutils
  module KeyTypes
    class << self
      def classes
        @classes ||= {}
      end

      def [] type
        classes[type]
      end

      def []= type, klass
        klass.send :define_method, :initialize, ->(id, description) do
          @id = id
          @description = description
        end
        klass.send :define_method, :type, ->() do
          type
        end
        classes[type] = klass
      end
    end
  end
end
